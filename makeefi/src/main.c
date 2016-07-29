#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <sys/wait.h>
#include <stdint.h>
#include <fcntl.h>

extern char **environ;
static const char* toolchain_prefix;

static char *edk2_path = "/media/Data/repositories/git/efidroid/testing/linuxtoolchain/edk2_min";
static const char *arg_srcdir = NULL;
static const char *arg_dscfile = NULL;
static const char *arg_inffile = NULL;
static const char *arg_archname = NULL;
static int arg_jobs = 1;
static int arg_silent = 0;
static int arg_quiet = 0;
static int arg_verbose = 0;
static struct poptOption optionsTable[] = {
    {
        "jobs", 'j', POPT_ARG_INT, &arg_jobs, 0,
        "Allow N jobs at once; 1 jobs with no arg.", "N"
    },
    {
        "arch", 'a', POPT_ARG_STRING, &arg_archname, 0,
        "Force architecture to use. This must the EDKII arch name e.g. X64", "NAME"
    },
    {
        "silent", 's', POPT_ARG_NONE, &arg_silent, 0,
        "Make use of silent mode of (n)make.", NULL
    },
    {
        "quiet", 'q', POPT_ARG_NONE, &arg_quiet, 0,
        "Disable all messages except FATAL ERRORS.", NULL
    },
    {
        "verbose", 'v', POPT_ARG_NONE, &arg_verbose, 0,
        "Turn on verbose output with informational messages printed, including library instances selected, final dependency expression, and warning messages, etc.", NULL
    },
    POPT_AUTOHELP
    { NULL, 0, 0, NULL, 0, NULL, NULL }
};

static void diehelp(const char* msg) {
    fprintf(stderr, "%s\n", msg);
    fprintf(stderr, "Try 'makeefi --help' for more information.\n");
    exit(1);
}

static void die(const char* msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

static int is_directory(const char *path)
{
    struct stat path_stat;
    int rc = stat(path, &path_stat);
    if (rc) return -ENOENT;
    return S_ISDIR(path_stat.st_mode);
}

static int node_exists(const char *path)
{
    struct stat path_stat;
    return !stat(path, &path_stat);
}

static int util_exec(char **args)
{
    pid_t pid;
    int status = 0;

    pid = vfork();
    if (pid==0) {
        status = execve(args[0], args, environ);
        exit(errno);
    } else if(pid<0) {
        die("execve error");
    } else {
        if(waitpid(pid, &status, 0)==-1)
            die("waitpid error");

        if (WIFEXITED(status)) {
            return -WEXITSTATUS(status);
        }
    }

    return -1;
}

static int util_exec_getbuf(char **args, char** outbuf)
{
    pid_t pid;
    int status = 0;
    int pipefd[2];
    char* buf = NULL;
    size_t bufsz = 0;
    int rc;

    rc = pipe(pipefd);
    if(rc) die("can't open pipe");

    pid = fork();
    if (pid==0) {
        close(pipefd[0]);

        dup2(pipefd[1], 1);
        dup2(pipefd[1], 2);

        status = execve(args[0], args, environ);
        exit(errno);
    } else if(pid<0) {
        die("execve error");
    } else {
        close(pipefd[1]);

        char buffer[1024];
        ssize_t bytes_read;
        while((bytes_read=read(pipefd[0], buffer, sizeof(buffer))) > 0) {
            buf = realloc(buf, bufsz + bytes_read);
            if(!buf) die("out of memory");
            memcpy(buf+bufsz, buffer, bytes_read);
            bufsz += bytes_read;
        }

        if(waitpid(pid, &status, 0)==-1)
            die("waitpid error");

        if(buf) {
            buf = realloc(buf, bufsz + 1);
            if(!buf) die("out of memory");
            buf[bufsz] = 0;
        }

        *outbuf = buf;

        if (WIFEXITED(status)) {
            return -WEXITSTATUS(status);
        }
    }

    return status;
}

static int util_shell(const char *_cmd)
{
    char *par[64];
    int i = 0;
    int rc;

    // duplicate arguments
    char* cmd = strdup(_cmd);
    if(!cmd) return -ENOMEM;

    // tool
    par[i++] = "/usr/bin/sh";

    // cmd
    par[i++] = "-c";
    par[i++] = cmd;

    // end
    par[i++] = (char *)0;

    rc = util_exec(par);

    // free arguments
    free(cmd);

    return rc;
}

static int util_shell_getbuf(const char *_cmd, char** outbuf)
{
    char *par[64];
    int i = 0;
    int rc;

    // duplicate arguments
    char* cmd = strdup(_cmd);
    if(!cmd) return -ENOMEM;

    // tool
    par[i++] = "/usr/bin/sh";

    // cmd
    par[i++] = "-c";
    par[i++] = cmd;

    // end
    par[i++] = (char *)0;

    rc = util_exec_getbuf(par, outbuf);

    // free arguments
    free(cmd);

    return rc;
}

static const char* get_tool_name(void) {
    int rc;
    char* buf = NULL;
    char* token;
    uint32_t version[3] = {0};
    uint32_t count;
    char cmdbuf[1024];

    rc = snprintf(cmdbuf, sizeof(cmdbuf), "%sgcc -v 2>&1 | tail -1 | awk '{print $3}'", toolchain_prefix);
    if(rc<0 || (size_t)rc>=sizeof(cmdbuf))
        die("can't build toolname command");

    rc = util_shell_getbuf(cmdbuf, &buf);
    if(rc) return "GCC44";

    size_t bufsz = strlen(buf);
    if(bufsz<1) return "GCC44";
    if(buf[bufsz-1]=='\n')
        buf[bufsz-1] = 0;

    for (count=0; (token = strsep(&buf, ".")); count++) {
        if(count>3) return "GCC44";

        version[count] = atoi(token);
    }

    if(version[0]==4 && version[1]==4)
        return "GCC45";
    if(version[0]==4 && version[1]==6)
        return "GCC46";
    if(version[0]==4 && version[1]==7)
        return "GCC47";
    if(version[0]==4 && version[1]==8)
        return "GCC48";
    if(version[0]==4 && version[1]==9)
        return "GCC49";
    if(version[0]==5 || version[0]==6)
        return "GCC49";

    return NULL;
}

static const char* get_tool_arch(void) {
    int rc;
    char* buf = NULL;
    char* token;
    char cmdbuf[1024];

    rc = snprintf(cmdbuf, sizeof(cmdbuf), "%sgcc -dumpmachine 2>&1", toolchain_prefix);
    if(rc<0 || (size_t)rc>=sizeof(cmdbuf))
        die("can't build toolname command");

    rc = util_shell_getbuf(cmdbuf, &buf);
    if(rc) return NULL;

    size_t bufsz = strlen(buf);
    if(bufsz<1) return NULL;
    if(buf[bufsz-1]=='\n')
        buf[bufsz-1] = 0;

    while ((token = strsep(&buf, "-"))) {
        if(!strcmp(token, "x86"))
            return "IA32";
        if(!strcmp(token, "x86_64"))
            return "X64";
        if(!strcmp(token, "arm"))
            return "ARM";
        if(!strcmp(token, "aarch64"))
            return "AARCH64";

        break;
    }

    return NULL;
}

static int util_cp(const char *source, const char *target)
{
    int rc;
    int i = 0;
    char *par[64];
    char *buf_source = NULL, *buf_target = NULL;

    // tool
    par[i++] = "/usr/bin/cp";

    // source
    buf_source = strdup(source);
    par[i++] = buf_source;

    // target
    buf_target = strdup(target);
    par[i++] = buf_target;

    // end
    par[i++] = (char *)0;

    // exec
    rc = util_exec(par);

    // cleanup
    free(buf_target);
    free(buf_source);

    return rc;
}

int main(int argc, const char **argv)
{
    char c;
    poptContext optCon;
    char* srcdir = NULL;
    char* cwd = NULL;
    char* npkgpath = NULL;
    int rc;
    char pathbuf[PATH_MAX];
    char* execline = NULL;
    
    // init popt
    optCon = poptGetContext(NULL, argc, argv, optionsTable, 0);
    poptSetOtherOptionHelp(optCon, "[options] SOURCE DSC [INF]\n\nSOURCE: directory to use as the workspace\nDSC: dsc file relative to workspace. Can also be the name of a globally registered dsc\nINF: inf file relative to workspace. If enabled, the dsc's Components section will be ignored\n");

    // parse options
    while ((c = poptGetNextOpt(optCon)) >= 0);
    arg_srcdir = poptGetArg(optCon);
    arg_dscfile = poptGetArg(optCon);
    arg_inffile = poptGetArg(optCon);

    // parsing error
    if (c < -1) {
        fprintf(stderr, "%s: %s\n",
                poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
                poptStrerror(c));
        return 1;
    }

    cwd = getcwd(NULL, 0);
    if(!cwd)
        die("can't get working directory");

    // validate args
    if(!arg_srcdir)
        diehelp("no source path given");
    if(!arg_dscfile)
        diehelp("no DSC given");

    // get edk2 path
    edk2_path = getenv("EDK2_PATH");
    if(!edk2_path)
        edk2_path = strdup("/opt/edk2");
    if(!edk2_path) die("out of memory");

    // get base dsc
    rc = snprintf(pathbuf, sizeof(pathbuf), "%s/%s", arg_srcdir, arg_dscfile);
    if(rc<0 || (size_t)rc>=sizeof(pathbuf))
        die("can't build DSC file path");
    if(!node_exists(pathbuf)) {
        rc = snprintf(pathbuf, sizeof(pathbuf), "%s/BaseTools/dsc_templates/%s.dsc", edk2_path, arg_dscfile);
        if(rc<0 || (size_t)rc>=sizeof(pathbuf))
            die("can't build DSC file path");

        if(!node_exists(pathbuf))
            die("DSC doesn't exist");

        arg_dscfile = strdup(pathbuf);

        // we need to add the inf to the components section
        if(arg_inffile) {
            // copy file to build dir
            rc = snprintf(pathbuf, sizeof(pathbuf), "%s/build.dsc", cwd);
            if(rc<0 || (size_t)rc>=sizeof(pathbuf))
                die("can't build DSC file path");
            rc = util_cp(arg_dscfile, pathbuf);
            if(rc) die("can't copy template dsc to build dir");

            // use the new copy
            free((void*)arg_dscfile);
            arg_dscfile = strdup(pathbuf);

            char character;
            int fd = open(arg_dscfile, O_WRONLY|O_APPEND);
            if(fd<0) die("can't open dsc file");

            character = '\n';
            write(fd, &character, 1);
            write(fd, arg_inffile, strlen(arg_inffile));

            close(fd);
        }
    }

    // resolve srcdir
    srcdir = realpath(arg_srcdir, NULL);
    if(!srcdir)
        diehelp("can't resolve source path");

    // create Conf directory
    rc = is_directory("Conf");
    if(rc==0) {
        die("'Conf' is not a directory");
    }
    else if(rc<0) {
        rc = mkdir("Conf", 0755);
        if(rc)
            die("can't create Conf directory");
    }

    // setup environment variables
    setenv("PYTHONDONTWRITEBYTECODE", "1", 1);

    rc = snprintf(pathbuf, sizeof(pathbuf), "%s/BaseTools", edk2_path);
    if(rc<0 || (size_t)rc>=sizeof(pathbuf))
        die("can't build EDK_TOOLS_PATH");
    setenv("EDK_TOOLS_PATH", pathbuf, 1);

    setenv("WORKSPACE", cwd, 1);

    rc = snprintf(pathbuf, sizeof(pathbuf), "%s/EdkCompatibilityPkg", edk2_path);
    if(rc<0 || (size_t)rc>=sizeof(pathbuf))
        die("can't build ECP_SOURCE");
    setenv("ECP_SOURCE", pathbuf, 1);
    setenv("EDK_SOURCE", pathbuf, 1);
    setenv("EFI_SOURCE", pathbuf, 1);

    // set PACKAGES_PATH
    char* pkgpath = getenv("PACKAGES_PATH");
    size_t npkgpathlen = 0;
    if(pkgpath)
            npkgpathlen += strlen(pkgpath)+1; // existing path and ':'
    npkgpathlen += strlen(edk2_path)+1;       // EDK2 path and ':'
    npkgpathlen += strlen(srcdir) + 1;        // srcdir and '\0'
    npkgpath = malloc(npkgpathlen);
    if(!npkgpath)
        die("out of memory");    
    rc = snprintf(npkgpath, npkgpathlen, "%s%s%s:%s",
              pkgpath?:"", pkgpath?":":""
            , edk2_path
            , srcdir);
    if(rc<0 || (size_t)rc>=npkgpathlen)
        die("can't build PACKAGES_PATH");
    setenv("PACKAGES_PATH", npkgpath, 1);

    // get toolchain prefix
    toolchain_prefix = getenv("CROSS_COMPILE");
    if(!toolchain_prefix) toolchain_prefix = "";

    // get tool name and arch
    const char* toolname = get_tool_name();
    if(!arg_archname)
        arg_archname = get_tool_arch();
    if(!arg_archname) die("can't detect target architecture");

    // set toolchain prefix
    rc = snprintf(pathbuf, sizeof(pathbuf), "%s_%s_PREFIX", toolname, arg_archname);
    if(rc<0 || (size_t)rc>=sizeof(pathbuf))
        die("can't build PREFIX");
    setenv(pathbuf, toolchain_prefix, 1);

    // start the build process
    const char* execline_fmt = "source \"%s/edksetup.sh\" && build -n %u -b RELEASE -a %s -t %s -p %s %s %s %s %s %s";
    size_t execline_len = strlen(execline_fmt);
    execline_len += strlen(edk2_path);    // edksetup.sh path
    execline_len += 10;                   // jobs
    execline_len += strlen(arg_archname); // arch
    execline_len += strlen(toolname);     // toolname
    execline_len += strlen(arg_dscfile);  // DSC
    execline_len += 2 + PATH_MAX;         // -m and INF
    execline_len += 2;                    // silent
    execline_len += 2;                    // quiet
    execline_len += 2;                    // verbose
    execline_len += 1;                    // 0 terminator
    execline = malloc(execline_len);
    if(!execline)
        die("out of memory");
    rc = snprintf(execline, execline_len, execline_fmt, edk2_path, arg_jobs, arg_archname, toolname, arg_dscfile,
                  arg_inffile?"-m":"", arg_inffile?:"",
                  arg_silent?"-s":"",
                  arg_quiet?"-q":"",
                  arg_verbose?"-v":""
                 );
    if(rc<0 || (size_t)rc>=execline_len)
        die("can't build edk2 exec line");
    rc = util_shell(execline);
    
    // cleanup
    free(execline);
    free(npkgpath);
    free(srcdir);
    free(cwd);
    poptFreeContext(optCon);
    return -rc;
}

