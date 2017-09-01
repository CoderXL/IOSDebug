//
//  dumpdecrypted.m
//  dumpdecrypted
//
//  Created by Carina on 15/2/5.
//  Copyright (c) 2015 Carina. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>


#define swap32(value) (((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) | ((value & 0x0000FF00) << 8) | ((value & 0x000000FF) << 24) )

typedef unsigned int uint32_t;
typedef unsigned long uintptr_t;

struct dyld_image_info
{
    const void* imageLoadAddress;
    const char* imageFilePath;
    uintptr_t imageFileModDate;
};

struct dyld_all_image_infos
{
    uint32_t version;
    uint32_t infoArrayCount;
    const struct dyld_image_info* infoArray;
};


__attribute__((constructor)) void decryptBundle()
{
    void* handle = dlopen("libSystem.B.dylib", 1);
    void* _dyld_get_all_image_infos = dlsym(handle, "_dyld_get_all_image_infos");
    struct dyld_all_image_infos* allinfo = ((struct dyld_all_image_infos* (*)())_dyld_get_all_image_infos)();
    const struct dyld_image_info* info = allinfo->infoArray;
    for(int i = 1;i < allinfo->infoArrayCount;i++)
    {
        if(strstr(info[i].imageFilePath, ".app"))
        {
			NSLog(@"%s", info[i].imageFilePath);
			dumptofile((mach_header*)info[i].imageLoadAddress, strstr(info[i].imageFilePath);
        }
    }

}

void dumptofile(mach_header* mh, char* path)
{
    struct load_command *lc;
    struct encryption_info_command *eic;
    struct fat_header *fh;
    struct fat_arch *arch;
    //    struct mach_header *mh;
    char buffer[1024];
    char rpath[4096],npath[4096]; /* should be big enough for PATH_MAX */
    unsigned int fileoffs = 0;
    off_t off_cryptid = 0, restsize;
    int i,fd,outfd;
    size_t r,n,toread;
    char *tmp;
    
    NSLog(@"mach-o decryption dumper\n\n");
    
    NSLog(@"DISCLAIMER: This tool is only meant for security research purposes, not for application crackers.\n\n");
    
    /* detect if this is a arm64 binary */
    if (mh->magic == MH_MAGIC_64) {
        lc = (struct load_command *)((unsigned char *)mh + sizeof(struct mach_header_64));
        NSLog(@"[+] detected 64bit ARM binary in memory.\n");
    } else { /* we might want to check for other errors here, too */
        lc = (struct load_command *)((unsigned char *)mh + sizeof(struct mach_header));
        NSLog(@"[+] detected 32bit ARM binary in memory.\n");
    }
    
    /* searching all load commands for an LC_ENCRYPTION_INFO load command */
    for (i=0; i<mh->ncmds; i++) {
        /*NSLog(@"Load Command (%d): %08x\n", i, lc->cmd);*/
        
        if (lc->cmd == LC_ENCRYPTION_INFO || lc->cmd == LC_ENCRYPTION_INFO_64) {
            eic = (struct encryption_info_command *)lc;
            
            /* If this load command is present, but data is not crypted then exit */
            if (eic->cryptid == 0) {
                break;
            }
            off_cryptid=(off_t)((void*)&eic->cryptid - (void*)mh);
            NSLog(@"[+] offset to cryptid found: @%p(from %p) = %llx\n", &eic->cryptid, mh, off_cryptid);
            
            NSLog(@"[+] Found encrypted data at address %08x of length %u bytes - type %u.\n", eic->cryptoff, eic->cryptsize, eic->cryptid);
            
            if (realpath(argv[0], rpath) == NULL) {
                strlcpy(rpath, argv[0], sizeof(rpath));
            }
            
            NSLog(@"[+] Opening %s for reading.\n", rpath);
            fd = open(rpath, O_RDONLY);
            if (fd == -1) {
                NSLog(@"[-] Failed opening.\n");
                return; //return; //_exit(1);
            }
            
            NSLog(@"[+] Reading header\n");
            n = read(fd, (void *)buffer, sizeof(buffer));
            if (n != sizeof(buffer)) {
                NSLog(@"[W] Warning read only %zu bytes\n", n);
            }
            
            NSLog(@"[+] Detecting header type\n");
            fh = (struct fat_header *)buffer;
            
            /* Is this a FAT file - we assume the right endianess */
            if (fh->magic == FAT_CIGAM) {
                NSLog(@"[+] Executable is a FAT image - searching for right architecture\n");
                arch = (struct fat_arch *)&fh[1];
                for (i=0; i<swap32(fh->nfat_arch); i++) {
                    if ((mh->cputype == swap32(arch->cputype)) && (mh->cpusubtype == swap32(arch->cpusubtype))) {
                        fileoffs = swap32(arch->offset);
                        NSLog(@"[+] Correct arch is at offset %u in the file\n", fileoffs);
                        break;
                    }
                    arch++;
                }
                if (fileoffs == 0) {
                    NSLog(@"[-] Could not find correct arch in FAT image\n");
                    return; //return; //_exit(1);
                }
            } else if (fh->magic == MH_MAGIC || fh->magic == MH_MAGIC_64) {
                NSLog(@"[+] Executable is a plain MACH-O image\n");
            } else {
                NSLog(@"[-] Executable is of unknown type\n");
                return; //return; //_exit(1);
            }
            
            /* extract basename */
            tmp = strrchr(rpath, '/');
            if (tmp == NULL) {
                NSLog(@"[-] Unexpected error with filename.\n");
                return; //_exit(1);
            }
            /// Documents
            NSArray  *paths     = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
            NSString *cachePath = [paths objectAtIndex:0];
            
            strlcpy(npath, cachePath.UTF8String, sizeof(npath));
            strlcat(npath, tmp, sizeof(npath));
            strlcat(npath, ".decrypted", sizeof(npath));
            strlcpy(buffer, npath, sizeof(buffer));
            
            NSLog(@"[+] Opening %s for writing.\n", npath);
            outfd = open(npath, O_RDWR|O_CREAT|O_TRUNC, 0644);
            if (outfd == -1) {
                if (strncmp("/private/var/mobile/Applications/", rpath, 33) == 0) {
                    NSLog(@"[-] Failed opening. Most probably a sandbox issue. Trying something different.\n");
                    
                    /* create new name */
                    strlcpy(npath, "/private/var/mobile/Applications/", sizeof(npath));
                    tmp = strchr(rpath+33, '/');
                    if (tmp == NULL) {
                        NSLog(@"[-] Unexpected error with filename.\n");
                        return; //_exit(1);
                    }
                    tmp++;
                    *tmp++ = 0;
                    strlcat(npath, rpath+33, sizeof(npath));
                    strlcat(npath, "tmp/", sizeof(npath));
                    strlcat(npath, buffer, sizeof(npath));
                    NSLog(@"[+] Opening %s for writing.\n", npath);
                    outfd = open(npath, O_RDWR|O_CREAT|O_TRUNC, 0644);
                    //Post Path Notification
                    NSString* NSpath=[[NSString stringWithUTF8String:npath] autorelease];
                    [[NSNotificationCenter defaultCenter] postNotificationName:RMASLRCenter
                      object:nil
                    userInfo:[NSDictionary dictionaryWithObject:NSpath forKey:@"Path"]];

                }
                if (outfd == -1) {
                    perror("[-] Failed opening");
                    NSLog(@"\n");
                    return; //_exit(1);
                }
            }
            else{
                //First Path Got Right
                    NSString* NSpath=[[NSString stringWithUTF8String:npath] autorelease];
                    [[NSNotificationCenter defaultCenter] postNotificationName:RMASLRCenter
                      object:nil
                    userInfo:[NSDictionary dictionaryWithObject:NSpath forKey:@"Path"]];

            }
            
            /* calculate address of beginning of crypted data */
            n = fileoffs + eic->cryptoff;
            
            restsize = lseek(fd, 0, SEEK_END) - n - eic->cryptsize;
            lseek(fd, 0, SEEK_SET);
            NSLog(@"[+] Copying the not encrypted start of the file\n");
            /* first copy all the data before the encrypted data */
            while (n > 0) {
                toread = (n > sizeof(buffer)) ? sizeof(buffer) : n;
                r = read(fd, buffer, toread);
                if (r != toread) {
                    NSLog(@"[-] Error reading file\n");
                    return; //_exit(1);
                }
                n -= r;
                
                r = write(outfd, buffer, toread);
                if (r != toread) {
                    NSLog(@"[-] Error writing file\n");
                    return; //_exit(1);
                }
            }
            
            /* now write the previously encrypted data */
            NSLog(@"[+] Dumping the decrypted data into the file\n");
            r = write(outfd, (unsigned char *)mh + eic->cryptoff, eic->cryptsize);
            if (r != eic->cryptsize) {
                NSLog(@"[-] Error writing file\n");
                return; //_exit(1);
            }
            
            /* and finish with the remainder of the file */
            n = (size_t)restsize;
            lseek(fd, eic->cryptsize, SEEK_CUR);
            NSLog(@"[+] Copying the not encrypted remainder of the file\n");
            while (n > 0) {
                toread = (n > sizeof(buffer)) ? sizeof(buffer) : n;
                r = read(fd, buffer, toread);
                if (r != toread) {
                    NSLog(@"[-] Error reading file\n");
                    return; //_exit(1);
                }
                n -= r;
                
                r = write(outfd, buffer, toread);
                if (r != toread) {
                    NSLog(@"[-] Error writing file\n");
                    return; //_exit(1);
                }
            }
            
            if (off_cryptid) {
                uint32_t zero=0;
                off_cryptid+=fileoffs;
                NSLog(@"[+] Setting the LC_ENCRYPTION_INFO->cryptid to 0 at offset %llx\n", off_cryptid);
                if (lseek(outfd, off_cryptid, SEEK_SET) != off_cryptid || write(outfd, &zero, 4) != 4) {
                    NSLog(@"[-] Error writing cryptid value\n");
                }
            }
            
            NSLog(@"[+] Closing original file\n");
            close(fd);
            NSLog(@"[+] Closing dump file\n");
            close(outfd);
            
            return; //_exit(1);
        }
        
        lc = (struct load_command *)((unsigned char *)lc+lc->cmdsize);
    }
    NSLog(@"[-] This mach-o file is not encrypted. Nothing was decrypted.\n");
    //Direct Copy mainExecutable
    NSURL* mainExeURL=[NSBundle mainBundle].executableURL;
    NSString* NewPath=[NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) objectAtIndex:0];
    NewPath=[NewPath stringByAppendingString:[[NSProcessInfo processInfo] processName]];
    [[NSFileManager defaultManager] copyItemAtURL:mainExeURL toURL:[NSURL URLWithString:NewPath] error:nil];
    [[NSNotificationCenter defaultCenter] postNotificationName:RMASLRCenter
                      object:nil
                    userInfo:[NSDictionary dictionaryWithObject:NewPath forKey:@"Path"]];

    [NewPath release];


    //
    return; //_exit(1);
}


