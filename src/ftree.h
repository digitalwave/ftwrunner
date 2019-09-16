/*
 * This file is part of the ftwrunner distribution (https://github.com/digitalwave/ftwrunner).
 * Copyright (c) 2019 digitalwave and Ervin Hegedüs.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <string>
#include <vector>
#include <sys/stat.h>
#include <dirent.h>
#include <iostream>

// Ftree class - helps to walk a directory structure
class Ftree {
    public:
        std::vector<std::string> dirlist;
        std::vector<std::string> filelist;
        Ftree(std::string path, std::string ruleset);
        void walk();
    private:
        void addfile(std::string fname);
        std::string path;
        std::string sruleset;
        struct stat dirpath;
        struct dirent *entry = NULL;
        std::string basename;
        std::string rulesetname;
        DIR *dirp = NULL;
};

Ftree::Ftree(std::string argpath, std::string ruleset) {
    sruleset = ruleset;
    path = argpath;
}

// add file to filelist if match with conditions
void Ftree::addfile(std::string fname) {
    // get basename
    basename = (fname.size() > 0) ? fname.substr(fname.find_last_of("/\\"), fname.size()-1) : "";
    // if it can contains the ext. ".yaml"
    if (basename.size() > 5) { // min lenght: a.yaml
        if (basename.substr(basename.size()-4, basename.size()-1) == "yaml") {
            // "/911100.yaml -> 911100"
            rulesetname = basename.substr(1, basename.size()-6);
            if (sruleset == "" || sruleset == rulesetname) {
                filelist.push_back(fname);
            }
        }
    }
}

// walk directory tree, avoid the recursion
void Ftree::walk() {
    std::string spath(path);
    if (stat(path.c_str(), &dirpath) == -1) {
        perror("File or directory not exists!\n");
        exit(EXIT_FAILURE);
    }
    // check path - if it's a directory, walk it recurse
    if ((dirpath.st_mode & S_IFMT) == S_IFDIR) {
        dirlist.push_back(spath);
    }
    // path is regular file
    else if ((dirpath.st_mode & S_IFMT) == S_IFREG) {
        addfile(spath);
    }
    // iterates the directory list, during extend it if dound a subdir
    for(unsigned long di = 0; di < dirlist.size(); di++) {
        std::string d(dirlist[di]);
        dirp = opendir(d.c_str());
        if (dirp != NULL) {
            // read directory
            while ((entry = readdir(dirp))) {
                std::string sentry(entry->d_name);
                // skip "." and ".."
                if (sentry != "." && sentry != "..") {
                    std::string sfull(d + "/" + sentry);
                    stat(sfull.c_str(), &dirpath);
                    if ((dirpath.st_mode & S_IFMT) == S_IFDIR) {
                        dirlist.push_back(sfull);
                    }
                    else if ((dirpath.st_mode & S_IFMT) == S_IFREG) {
                        addfile(sfull);
                    }
                    sfull = "";
                }
                sentry = "";
            }
        }
        else {
            std::cout << "Can't open directory: " << d << std::endl;
        }
    }
}