# edk2-linux-toolchain

simplifies UEFI development with a easy to use toolchain and make tool

```
Usage: makeefi [options] SOURCE DSC [INF]

SOURCE: directory to use as the workspace
DSC: dsc file relative to workspace. Can also be the name of a globally registered dsc
INF: inf file relative to workspace. If enabled, the dsc's Components section will be ignored

  -j, --jobs=N        Allow N jobs at once; 1 jobs with no arg.
  -a, --arch=NAME     Force architecture to use. This must the EDKII arch name e.g. X64
  -s, --silent        Make use of silent mode of (n)make.
  -q, --quiet         Disable all messages except FATAL ERRORS.
  -v, --verbose       Turn on verbose output with informational messages printed, including library instances selected, final dependency
                      expression, and warning messages, etc.

Help options:
  -?, --help          Show this help message
      --usage         Display brief usage message

```
