/*
 * wss-v2.c	Estimate the working set size (WSS) for a process on Linux.
 *		Version 2: suited for large processes.
 *
 * This is a proof of concept that uses idle page tracking from Linux 4.3+, for
 * a page-based WSS estimation. This version snapshots the entire system's idle
 * page flags, which is efficient for analyzing large processes, but not tiny
 * processes. For those, see wss-v1.c. There is also wss.pl, which uses can be
 * over 10x faster and works on older Linux, however, uses the referenced page
 * flag and has its own caveats. These tools can be found here:
 *
 * http://www.brendangregg.com/wss.pl
 *
 * Currently written for x86_64 and default page size only. Early version:
 * probably has bugs.
 *
 * COMPILE: gcc -o wss-v1 wss-v1.c
 *
 * REQUIREMENTS: Linux 4.3+
 *
 * USAGE: wss PID duration(s)
 *
 * COLUMNS:
 *	- Est(s):  Estimated WSS measurement duration: this accounts for delays
 *	           with setting and reading pagemap data, which inflates the
 *	           intended sleep duration.
 *	- Ref(MB): Referenced (Mbytes) during the specified duration.
 *	           This is the working set size metric.
 *
 * WARNING: This tool sets and reads system and process page flags, which can
 * take over one second of CPU time, during which application may experience
 * slightly higher latency (eg, 5%). Consider these overheads. Also, this is
 * activating some new kernel code added in Linux 4.3 that you may have never
 * executed before. As is the case for any such code, there is the risk of
 * undiscovered kernel panics (I have no specific reason to worry, just being
 * paranoid). Test in a lab environment for your kernel versions, and consider
 * this experimental: use at your own risk.
 *
 * Copyright 2018 Netflix, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 *
 * 13-Jan-2018	Brendan Gregg	Created this.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>

//zyj---
#include <sys/mman.h>

// see Documentation/vm/pagemap.txt:
#define PFN_MASK		(~(0x1ffLLU << 55))

#define PATHSIZE		128
#define LINESIZE		256
#define PAGEMAP_CHUNK_SIZE	8
#define IDLEMAP_CHUNK_SIZE	8
#define IDLEMAP_BUF_SIZE	4096 * 16

// big enough to span 740 Gbytes:
#define MAX_IDLEMAP_SIZE	(20 * 1024 * 1024)

// from mm/page_idle.c:
#ifndef BITMAP_CHUNK_SIZE
#define BITMAP_CHUNK_SIZE	8
#endif

#ifndef PAGE_OFFSET
#define PAGE_OFFSET		0xffff880000000000LLU
#endif

// globals
int g_debug = 0;		// 1 == some, 2 == verbose
unsigned long long g_activepages = 0;
unsigned long long g_walkedpages = 0;
char *g_idlepath = "/sys/kernel/mm/page_idle/bitmap";
unsigned long long *g_idlebuf = NULL;
unsigned long long g_idlebufsize;

//zyj---
#define RECORD_FILE_SIZE 100 * 1024 * 1024 //100MB
int record_fd;
unsigned long long *g_record_buf;
unsigned g_record_cnt = 0;
	//setidlemap
int g_idlefd = -1;
	//loadidlemap
char g_buf[IDLEMAP_BUF_SIZE];
	//walkmaps
FILE *g_mapsfile;
char g_mapspath[PATHSIZE];
	//mapidle
char g_pagepath[PATHSIZE];
int g_pagefd;

/*
 * This code must operate on bits in the pageidle bitmap and process pagemap.
 * Doing this one by one via syscall read/write on a large process can take too
 * long, eg, 7 minutes for a 130 Gbyte process. Instead, I copy (snapshot) the
 * idle bitmap and pagemap into our memory with the fewest syscalls allowed,
 * and then process them with load/stores. Much faster, at the cost of some memory.
 */

int mapidle(pid_t pid, unsigned long long mapstart, unsigned long long mapend)
{
	//char pagepath[PATHSIZE];
	//int pagefd;
	char *line;
	unsigned long long offset, i, pagemapp, pfn, idlemapp, idlebits;
	int pagesize;
	int err = 0;
	unsigned long long *pagebuf, *p;
	unsigned long long pagebufsize;
	ssize_t len;
	
	// XXX: handle huge pages
	pagesize = getpagesize();

	pagebufsize = (PAGEMAP_CHUNK_SIZE * (mapend - mapstart)) / pagesize;
	if ((pagebuf = malloc(pagebufsize)) == NULL) {
		printf("Can't allocate memory for pagemap buf (%lld bytes)",
		    pagebufsize);
		return 1;
	}

	// open pagemap for virtual to PFN translation
	// if (sprintf(pagepath, "/proc/%d/pagemap", pid) < 0) {
	// 	printf("Can't allocate memory.");
	// 	return 1;
	// }
	// if ((pagefd = open(g_pagepath, O_RDONLY)) < 0) {
	// 	perror("Can't read pagemap file");
	// 	return 2;
	// }

	// cache pagemap to get PFN, then operate on PFN from idlemap
	offset = PAGEMAP_CHUNK_SIZE * mapstart / pagesize;
	if (lseek(g_pagefd, offset, SEEK_SET) < 0) {
		printf("Can't seek pagemap file\n");
		err = 1;
		goto out;
	}
	p = pagebuf;

	// optimized: read this in one syscall
	if (read(g_pagefd, p, pagebufsize) < 0) {
		perror("Read page map failed.");
		err = 1;
		goto out;
	}

	for (i = 0; i < pagebufsize / sizeof (unsigned long long); i++) {
		// convert virtual address p to physical PFN
		pfn = p[i] & PFN_MASK;
		if (pfn == 0)
			continue;

		// read idle bit
		idlemapp = (pfn / 64) * BITMAP_CHUNK_SIZE;
		if (idlemapp > g_idlebufsize) {
			printf("ERROR: bad PFN read from page map.\n");
			err = 1;
			goto out;
		}
		idlebits = g_idlebuf[idlemapp];
		if (g_debug > 1) {
			printf("R: p %llx pfn %llx idlebits %llx\n",
			    p[i], pfn, idlebits);
		}

		if (!(idlebits & (1ULL << (pfn % 64)))) {
			g_activepages++;
			unsigned long long i;
			for(i=0; i<g_record_cnt; i++){
				if(g_record_buf[i] >> 12 == pfn){
					g_record_buf[i]++;
					printf("zyj---g_record_buf[%u]=%lx, pfn=%lx\n", i, g_record_buf[i], pfn);
					break;
				}
			}
			if(i == g_record_cnt){
				g_record_buf[i] = pfn << 12;
				g_record_cnt++;
				printf("zyj---new pfn=%lx, cnt=%u\n", g_record_buf[i], i);
			}
		}
		g_walkedpages++;
	}

out:
	//close(g_pagefd);

	return err;
}

int walkmaps(pid_t pid)
{
	//FILE *mapsfile;
	//char mapspath[PATHSIZE];
	char line[LINESIZE];
	size_t len = 0;
	unsigned long long mapstart, mapend;

	// read virtual mappings
	// if (sprintf(mapspath, "/proc/%d/maps", pid) < 0) {
	// 	printf("Can't allocate memory. Exiting.");
	// 	exit(1);
	// }
	// if ((g_mapsfile = fopen(g_mapspath, "r")) == NULL) {
	// 	perror("Can't read maps file");
	// 	exit(2);
	// }

	while (fgets(line, sizeof (line), g_mapsfile) != NULL) {
		sscanf(line, "%llx-%llx", &mapstart, &mapend);
		if (g_debug)
			printf("MAP %llx-%llx\n", mapstart, mapend);
		if (mapstart > PAGE_OFFSET)
			continue;	// page idle tracking is user mem only
		if (mapidle(pid, mapstart, mapend)) {
			printf("Error setting map %llx-%llx. Exiting.\n",
			    mapstart, mapend);
		}
	}
	fseek(g_mapsfile, 0, SEEK_SET);
	//fclose(g_mapsfile);

	return 0;
}

int setidlemap()
{
	char *p;
	int idlefd, i;
	// optimized: large writes allowed here:
	// char buf[IDLEMAP_BUF_SIZE];

	// for (i = 0; i < sizeof (buf); i++)
	// 	buf[i] = 0xff;

	// set entire idlemap flags
	// if(g_idlefd < 0){
	// 	if ((g_idlefd = open(g_idlepath, O_RDWR)) < 0) {
	// 		perror("Can't write idlemap file");
	// 		exit(2);
	// 	}
	// 	printf("zyj---setidle g_idlefd=%d\n", g_idlefd);
	// }
	// only sets user memory bits; kernel is silently ignored
	while (write(g_idlefd, &g_buf, sizeof(g_buf)) > 0) {;}

	lseek(g_idlefd, 0, SEEK_SET);
	//close(idlefd);

	return 0;
}

int loadidlemap()
{
	unsigned long long *p;
	int idlefd;
	ssize_t len;

	// if(g_idlebuf == NULL){
	// 	if ((g_idlebuf = malloc(MAX_IDLEMAP_SIZE)) == NULL) {
	// 		printf("Can't allocate memory for idlemap buf (%d bytes)",
	// 			MAX_IDLEMAP_SIZE);
	// 		exit(1);
	// 	}
	// }
	// copy (snapshot) idlemap to memory
	if(g_idlefd < 0){
		if ((g_idlefd = open(g_idlepath, O_RDWR)) < 0) {
			perror("Can't write idlemap file");
			exit(2);
		}
		printf("zyj---loadidle g_idlefd=%d\n", g_idlefd);
	}
	p = g_idlebuf;
	// unfortunately, larger reads do not seem supported
	while ((len = read(g_idlefd, p, IDLEMAP_CHUNK_SIZE)) > 0) {
		p += IDLEMAP_CHUNK_SIZE;
		g_idlebufsize += len;
	}
	lseek(g_idlefd, 0, SEEK_SET);
	//close(idlefd);

	return 0;
}

int main(int argc, char *argv[])
{
	pid_t pid;
	double duration, mbytes;
	int times;
	static struct timeval ts1, ts2, ts3, ts4;
	unsigned long long set_us, read_us, dur_us, slp_us, est_us;

	for (int i = 0; i < sizeof (g_buf); i++)
		g_buf[i] = 0xff;

	// options
	if (argc < 4) {
		printf("USAGE: wss PID duration(s) times\n");
		exit(0);
	}	
	pid = atoi(argv[1]);
	duration = atof(argv[2]);
	times = atoi(argv[3]);
	if (duration < 0.01) {
		printf("Interval too short. Exiting.\n");
		return 1;
	}
	printf("Watching PID %d page references during %.2f seconds...\n",
	    pid, duration);
	
	//record active pfn
	if ((record_fd = open("/home/yijiezhong/wss-test/1.tmp", O_CREAT|O_RDWR)) < 0) {
		perror("record_fd open fail");
		exit(2);
	}
	if ((ftruncate(record_fd, RECORD_FILE_SIZE)) < 0) {
		perror("record_fd ftruncate fail");
		exit(2);
	}
	g_record_buf = (unsigned long long*)mmap(NULL, RECORD_FILE_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, record_fd, 0);
	if(g_record_buf == MAP_FAILED){
		perror("record_fd mmap fail");
		exit(2);
	}
	for(int i=0; i<RECORD_FILE_SIZE/8; i++)
		g_record_buf[i] = 0;

	//loadidlemap
	if ((g_idlebuf = malloc(MAX_IDLEMAP_SIZE)) == NULL) {
		printf("loadidlemap g_idlebuf Can't allocate memory for idlemap buf (%d bytes)",
			MAX_IDLEMAP_SIZE);
		exit(1);
	}
	//setidlemap
	if ((g_idlefd = open(g_idlepath, O_RDWR)) < 0) {
		perror("setidlemap g_idlefd Can't write idlemap file");
		exit(2);
	}

	//walkmaps
	if (sprintf(g_mapspath, "/proc/%d/maps", pid) < 0) {
		printf("walkmaps g_mapspath Can't allocate memory. Exiting.");
		exit(1);
	}
	if ((g_mapsfile = fopen(g_mapspath, "r")) == NULL) {
		perror("walkmaps g_mapsfile Can't read maps file");
		exit(2);
	}
	//mapidle
	if (sprintf(g_pagepath, "/proc/%d/pagemap", pid) < 0) {
		printf("mapidle g_pagepath Can't allocate memory.");
		exit(1);
	}
	if ((g_pagefd = open(g_pagepath, O_RDONLY)) < 0) {
		perror("mapidle g_pagefd Can't read pagemap file");
		exit(2);
	}

	for(int i=0; i<times; i++){
		// set idle flags
		gettimeofday(&ts1, NULL);
		setidlemap();

		// sleep
		gettimeofday(&ts2, NULL);
		usleep((int)(duration * 1000000));
		gettimeofday(&ts3, NULL);

		// read idle flags
		loadidlemap();
		walkmaps(pid);
		gettimeofday(&ts4, NULL);

		// calculate times
		set_us = 1000000 * (ts2.tv_sec - ts1.tv_sec) +
			(ts2.tv_usec - ts1.tv_usec);
		slp_us = 1000000 * (ts3.tv_sec - ts2.tv_sec) +
			(ts3.tv_usec - ts2.tv_usec);
		read_us = 1000000 * (ts4.tv_sec - ts3.tv_sec) +
			(ts4.tv_usec - ts3.tv_usec);
		dur_us = 1000000 * (ts4.tv_sec - ts1.tv_sec) +
			(ts4.tv_usec - ts1.tv_usec);
		est_us = dur_us - (set_us / 2) - (read_us / 2);
		if (g_debug) {
			printf("set time  : %.3f s\n", (double)set_us / 1000000);
			printf("sleep time: %.3f s\n", (double)slp_us / 1000000);
			printf("read time : %.3f s\n", (double)read_us / 1000000);
			printf("dur time  : %.3f s\n", (double)dur_us / 1000000);
			// assume getpagesize() sized pages:
			printf("referenced: %u pages, %u Kbytes\n", g_activepages,
				g_activepages * getpagesize());
			printf("walked    : %u pages, %u Kbytes\n", g_walkedpages,
				g_walkedpages * getpagesize());
		}

		// assume getpagesize() sized pages:
		mbytes = (g_activepages * getpagesize()) / (1024 * 1024);
		printf("%-7s %10s\n", "Est(s)", "Ref(MB)");
		printf("%-7.3f %10.2f\n", (double)est_us / 1000000, mbytes);

		g_activepages = 0;
		g_walkedpages = 0;
	}

	close(g_idlefd);
	free(g_idlebuf);
	munmap(g_record_buf, RECORD_FILE_SIZE);
	return 0;
}
