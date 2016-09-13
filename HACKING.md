---
title: Conventions for working on Quagga 
papersize: a4paper
geometry: scale=0.82
fontsize: 11pt
toc: true
date: \today
include-before: 
  \large This is a living document. 

  \large This is a living document describing the processes and guidelines
   for working on Quagga. You *must* read Section
   ["REQUIRED READING"](#sec:required), before contributing to Quagga.

   Suggestions for updates, via the
  [quagga-dev list](http://lists.quagga.net/mailman/listinfo/quagga-dev),
  are welcome. \newpage
...

\newpage

REQUIRED READING {#sec:required}
================

Note well: By proposing a change to Quagga, by whatever means, you are
implicitly agreeing:
                                                                              
-   To licence your contribution according to the licence of any files in
    Quagga being modified, _and_ according to the COPYING file in the
    top-level directory of Quagga, other than where the contribution
    explicitly and clearly indicates otherwise.

-   That it is your responsibility to ensure you hold whatever rights are
    required to be able to contribute your changes under the licenses of the
    files in Quagga being modified, and the top-level COPYING file.
                                                                              
-   That it is your responsibility to give with the contribution a full
    account of all interests held and claims in the contribution; such as
    through copyright, trademark and patent laws or otherwise; that are known
    to you or your associates (e.g.  your employer).

Before contributing to Quagga, you *must*  also read 
[Section COMMIT MESSAGES](#sec:commit-messages).  You _should_ ideally read the entire
document, as it contains useful information on the community norms and how
to implement them.


GUIDELINES FOR HACKING ON QUAGGA {#sec:guidelines}
================================

GNU coding standards apply.  Indentation follows the result of
invoking GNU indent (as of 2.2.8a) with the -–nut argument.

Originally, tabs were used instead of spaces, with tabs are every 8 columns. 
However, tab’s interoperability issues mean space characters are now preferred for
new changes. We generally only clean up whitespace when code is unmaintainable
due to whitespace issues, to minimise merging conflicts.

Be particularly careful not to break platforms/protocols that you
cannot test.

New code should have good comments, which explain why the code is correct.
Changes to existing code should in many cases upgrade the comments when
necessary for a reviewer to conclude that the change has no unintended
consequences.

Each file in the Git repository should have a git format-placeholder (like
an RCS Id keyword), somewhere very near the top, commented out appropriately
for the file type. The placeholder used for Quagga (replacing \<dollar\>
with \$) is:

`$QuaggaId: <dollar>Format:%an, %ai, %h<dollar> $`

See line 2 of HACKING.tex, the source for this document, for an example.

This placeholder string will be expanded out by the ‘git archive’ commands,
which is used to generate the tar archives for snapshots and releases.

Please document fully the proper use of a new function in the header file
in which it is declared.  And please consult existing headers for
documentation on how to use existing functions.  In particular, please consult
these header files:

<span>lib/log.h</span> logging levels and usage guidance

<span>[more to be added]</span>

If changing an exported interface, please try to deprecate the interface in
an orderly manner. If at all possible, try to retain the old deprecated
interface as is, or functionally equivalent. Make a note of when the
interface was deprecated and guard the deprecated interface definitions in
the header file, i.e.:

    /* Deprecated: 20050406 */
    #if !defined(QUAGGA_NO_DEPRECATED_INTERFACES)
    #warning "Using deprecated <libname> (interface(s)|function(s))"
    ...
    #endif /* QUAGGA_NO_DEPRECATED_INTERFACES */

This is to ensure that the core Quagga sources do not use the deprecated
interfaces (you should update Quagga sources to use new interfaces, if
applicable), while allowing external sources to continue to build. 
Deprecated interfaces should be excised in the next unstable cycle.

Note: If you wish, you can test for GCC and use a function
marked with the ’deprecated’ attribute.  However, you must provide the
warning for other compilers.

If changing or removing a command definition, *ensure* that you
properly deprecate it - use the \_DEPRECATED form of the appropriate DEFUN
macro. This is *critical*.  Even if the command can no longer
function, you *MUST* still implement it as a do-nothing stub.

Failure to follow this causes grief for systems administrators, as an
upgrade may cause daemons to fail to start because of unrecognised commands. 
Deprecated commands should be excised in the next unstable cycle.  A list of
deprecated commands should be collated for each release.

See also [Section SHARED LIBRARY VERSIONING](#sec:dll-versioning) below.

YOUR FIRST CONTRIBUTIONS
========================

Routing protocols can be very complex sometimes. Then, working with an
Opensource community can be complex too, but usually friendly with
anyone who is ready to be willing to do it properly.

-   First, start doing simple tasks. Quagga’s patchwork is a good place
    to start with. Pickup some patches, apply them on your git trie,
    review them and send your ack’t or review comments. Then, a
    maintainer will apply the patch if ack’t or the author will have to
    provide a new update. It help a lot to drain the patchwork queues.
    See <http://patchwork.quagga.net/project/quagga/list/>

-   The more you’ll review patches from patchwork, the more the Quagga’s
    maintainers will be willing to consider some patches you will be
    sending.

-   start using git clone, pwclient
    <http://patchwork.quagga.net/help/pwclient/>

        $ pwclient list -s new
        ID    State        Name
        --    -----        ----
        179   New          [quagga-dev,6648] Re: quagga on FreeBSD 4.11 (gcc-2.95)
        181   New          [quagga-dev,6660] proxy-arp patch
        [...]

        $ pwclient git-am 1046

HANDY GUIDELINES FOR MAINTAINERS
================================

Get your cloned trie:

      git clone vjardin@git.sv.gnu.org:/srv/git/quagga.git

Apply some ack’t patches:

      pwclient git-am 1046
        Applying patch #1046 using 'git am'
        Description: [quagga-dev,11595] zebra: route_unlock_node is missing in "show ip[v6] route <prefix>" commands
        Applying: zebra: route_unlock_node is missing in "show ip[v6] route <prefix>" commands

Run a quick review. If the ack’t was not done properly, you know who you have
to blame.

Push the patches:

      git push

Set the patch to accepted on patchwork

      pwclient update -s Accepted 1046

COMPILE-TIME CONDITIONAL CODE
=============================

Please think very carefully before making code conditional at compile time,
as it increases maintenance burdens and user confusion. In particular,
please avoid gratuitous -–enable-… switches to the configure script -
typically code should be good enough to be in Quagga, or it shouldn’t be
there at all.

When code must be compile-time conditional, try have the compiler make it
conditional rather than the C pre-processor - so that it will still be
checked by the compiler, even if disabled. I.e.  this:

        if (SOME_SYMBOL)
          frobnicate();

rather than:

      #ifdef SOME_SYMBOL
      frobnicate ();
      #endif /* SOME_SYMBOL */

Note that the former approach requires ensuring that SOME\_SYMBOL will
be defined (watch your AC\_DEFINEs).

COMMIT MESSAGES {#sec:commit-messages}
======================================

The commit message requirements are:

-   The message *MUST* provide a suitable one-line summary followed by a
    blank line as the very first line of the message, in the form:

    `topic: high-level, one line summary`

    Where topic would tend to be name of a subdirectory, and/or daemon, unless
    there’s a more suitable topic (e.g. ’build’). This topic is used to
    organise change summaries in release announcements.

-   It should have a suitable “body”, which tries to address the
    following areas, so as to help reviewers and future browsers of the
    code-base understand why the change is correct (note also the code
    comment requirements):

    -   The motivation for the change (does it fix a bug, if so which?
        add a feature?)

    -   The general approach taken, and trade-offs versus any other
        approaches.

    -   Any testing undertaken or other information affecting the confidence
        that can be had in the change.

    -   Information to allow reviewers to be able to tell which specific
        changes to the code are intended (and hence be able to spot any accidental
        unintended changes).

-   The commit message *must* give details of all the authors of the change,
    beyond the person listed in the Author field.  Any and all affiliations
    which may have a bearing on copyright in any way should be clearly
    stated, unless those affiliations are already obvious from other
    details, e.g.  from the email address.  This would cover employment and
    contracting obligations (give details).
                                                             
-   If the change introduces a new dependency on any code or other
    copyrighted material, please explicitly note this.  Give details of what
    that external material is, the copyright licence the material may be
    used under, and the nature of the dependency.

The one-line summary must be limited to 54 characters, and all other
lines to 72 characters.

Commit message bodies in the Quagga project have typically taken the
following form:

-   An optional introduction, describing the change generally.

-   A short description of each specific change made, preferably:

    -   file by file

        -   function by function (use of “ditto”, or globs is allowed)

Contributors are strongly encouraged to follow this form.

This itemised commit messages allows reviewers to have confidence that the
author has self-reviewed every line of the patch, as well as providing
reviewers a clear index of which changes are intended, and descriptions for
them (C-to-english descriptions are not desirable - some discretion is
useful).  For short patches, a per-function/file break-down may be
redundant.  For longer patches, such a break-down may be essential.  A
contrived example (where the general discussion is obviously somewhat
redundant, given the one-line summary):

>     zebra: Enhance frob FSM to detect loss of frob
>
>     Add a new DOWN state to the frob state machine to allow the barinator to
>     detect loss of frob.
>
>     * frob.h: (struct frob) Add DOWN state flag.
>     * frob.c: (frob_change) set/clear DOWN appropriately on state change.
>     * bar.c: (barinate) Check frob for DOWN state.

Please have a look at the git commit logs to get a feel for what the norms
are.

Note that the commit message format follows git norms, so that “git log
–oneline” will have useful output.

HACKING THE BUILD SYSTEM
========================

If you change or add to the build system (configure.ac, any Makefile.am,
etc.), try to check that the following things still work:

-   make dist

-   resulting dist tarball builds

-   out-of-tree builds

The quagga.net site relies on make dist to work to generate snapshots. It
must work. Common problems are to forget to have some additional file
included in the dist, or to have a make rule refer to a source file without
using the srcdir variable.

RELEASE PROCEDURE
=================

-   Tag the appropriate commit with a release tag (follow existing
    conventions).

    [This enables recreating the release, and is just good CM practice.]

-   Create a fresh tar archive of the quagga.net repository, and do a
    test build:

            vim configure.ac
            git commit -m "release: 0.99.99.99"
            git tag -u 54CD2E60 quagga-0.99.99.99
            git push savannah tag quagga-0.99.99.99

            git archive --prefix=quagga-release/ quagga-0.99.99.99 | tar xC /tmp
            git log quagga-0.99.99.98..quagga-0.99.99.99 > \
               /tmp/quagga-release/quagga-0.99.99.99.changelog.txt
            cd /tmp/quagga-release

            autoreconf -i
            ./configure
            make
            make dist-gzip

            gunzip < quagga-0.99.99.99.tar.gz > quagga-0.99.99.99.tar
            xz -6e < quagga-0.99.99.99.tar > quagga-0.99.99.99.tar.xz
            gpg -u 54CD2E60 -a --detach-sign quagga-0.99.99.99.tar

            scp quagga-0.99.99.99.* username@dl.sv.nongnu.org:/releases/quagga
          

    Do NOT do this in a subdirectory of the Quagga sources, autoconf
    will think it’s a sub-package and fail to include neccessary files.

-   Add the version number on https://bugzilla.quagga.net/, under
    Administration, Products, “Quagga”, Edit versions, Add a version.

-   Edit the wiki on
    https://wiki.quagga.net/wiki/index.php/Release\_status

-   Post a news entry on Savannah

-   Send a mail to quagga-dev and quagga-users

The tarball which ‘make dist’ creates is the tarball to be released! The
git-archive step ensures you’re working with code corresponding to that in
the official repository, and also carries out keyword expansion. If any
errors occur, move tags as needed and start over from the fresh checkouts.
Do not append to tarballs, as this has produced non-standards-conforming
tarballs in the past.

See also: <http://wiki.quagga.net/index.php/Main/Processes>

[TODO: collation of a list of deprecated commands. Possibly can be
scripted to extract from vtysh/vtysh\_cmd.c]

TOOL VERSIONS
=============

Require versions of support tools are listed in INSTALL.quagga.txt.
Required versions should only be done with due deliberation, as it can
cause environments to no longer be able to compile quagga.

SHARED LIBRARY VERSIONING {#sec:dll-versioning}
=========================

[this section is at the moment just gdt’s opinion]

Quagga builds several shared libaries (lib/libzebra, ospfd/libospf,
ospfclient/libsopfapiclient).  These may be used by external programs,
e.g. a new routing protocol that works with the zebra daemon, or
ospfapi clients.  The libtool info pages (node Versioning) explain
when major and minor version numbers should be changed.  These values
are set in Makefile.am near the definition of the library.  If you
make a change that requires changing the shared library version,
please update Makefile.am.

libospf exports far more than it should, and is needed by ospfapi
clients.  Only bump libospf for changes to functions for which it is
reasonable for a user of ospfapi to call, and please err on the side
of not bumping.

There is no support intended for installing part of zebra.  The core
library libzebra and the included daemons should always be built and
installed together.

GIT COMMIT SUBMISSION {#sec:git-submission}
=====================

The preferred method for submitting changes is to provide git commits via a
publicly-accessible git repository, which the maintainers can easily pull.

The commits should be in a branch based off the Quagga.net master - a
“feature branch”.  Ideally there should be no commits to this branch other
than those in master, and those intended to be submitted.  However, merge
commits to this branch from the Quagga master are permitted, though strongly
discouraged - use another (potentially local and throw-away) branch to test
merge with the latest Quagga master.

Recommended practice is to keep different logical sets of changes on
separate branches - “topic” or “feature” branches.  This allows you to still
merge them together to one branch (potentially local and/or “throw-away”)
for testing or use, while retaining smaller, independent branches that are
easier to merge.

All content guidelines in [Section PATCH SUBMISSION](#sec:patch-submission)
apply.

PATCH SUBMISSION {#sec:patch-submission}
================

-   For complex changes, contributors are strongly encouraged to first
    start a design discussion on the quagga-dev list *before* starting
    any coding.

-   Send a clean diff against the ’master’ branch of the quagga.git
    repository, in unified diff format, preferably with the ’-p’
    argument to show C function affected by any chunk, and with the -w
    and -b arguments to minimise changes. E.g:

    git diff -up mybranch..remotes/quagga.net/master

    It is preferable to use git format-patch, and even more preferred to
    publish a git repository (see 
    [Section GIT COMMIT SUBMISSION](#sec:git-submission)).

    If not using git format-patch, Include the commit message in the
    email.

-   After a commit, code should have comments explaining to the reviewer
    why it is correct, without reference to history. The commit message
    should explain why the change is correct.

-   Include NEWS entries as appropriate.

-   Include only one semantic change or group of changes per patch.

-   Do not make gratuitous changes to whitespace. See the w and b
    arguments to diff.

-   Changes should be arranged so that the least controversial and most
    trivial are first, and the most complex or more controversial are
    last. This will maximise how many the Quagga maintainers can merge,
    even if some other commits need further work.

-   Providing a unit-test is strongly encouraged. Doing so will make it
    much easier for maintainers to have confidence that they will be
    able to support your change.

-   New code should be arranged so that it easy to verify and test. E.g.
    stateful logic should be separated out from functional logic as much
    as possible: wherever possible, move complex logic out to smaller
    helper functions which access no state other than their arguments.

-   State on which platforms and with what daemons the patch has been
    tested. Understand that if the set of testing locations is small,
    and the patch might have unforeseen or hard to fix consequences that
    there may be a call for testers on quagga-dev, and that the patch
    may be blocked until test results appear.

    If there are no users for a platform on quagga-dev who are able and
    willing to verify -current occasionally, that platform may be
    dropped from the “should be checked” list.

PATCH APPLICATION
=================

-   Only apply patches that meet the submission guidelines.

-   If the patch might break something, issue a call for testing on the
    mailing-list.

-   Give an appropriate commit message (see above), and use the –author
    argument to git-commit, if required, to ensure proper attribution
    (you should still be listed as committer)

-   Immediately after commiting, double-check (with git-log and/or
    gitk). If there’s a small mistake you can easily fix it with ‘git
    commit –amend ..’

-   When merging a branch, always use an explicit merge commit. Giving
    –no-ff ensures a merge commit is created which documents “this human
    decided to merge this branch at this time”.

STABLE PLATFORMS AND DAEMONS
============================

The list of platforms that should be tested follow.  This is a list
derived from what quagga is thought to run on and for which
maintainers can test or there are people on quagga-dev who are able
and willing to verify that -current does or does not work correctly.

-   BSD (Free, Net or Open, any platform)

-   GNU/Linux (any distribution, i386)

-   Solaris (strict alignment, any platform)

-   future: NetBSD/sparc64

The list of daemons that are thought to be stable and that should be
tested are:

-   zebra

-   bgpd

-   ripd

-   ospfd

-   ripngd

Daemons which are in a testing phase are

-   ospf6d

-   isisd

-   watchquagga

IMPORT OR UPDATE VENDOR SPECIFIC ROUTING PROTOCOLS
==================================================

The source code of Quagga is based on two vendors:

`zebra_org` (<http://www.zebra.org/>) `isisd_sf`
(<http://isisd.sf.net/>)

To import code from further sources, e.g. for archival purposes without
necessarily having to review and/or fix some changeset, create a branch
from ‘master’:

        git checkout -b archive/foo master
        <apply changes>
        git commit -a "Joe Bar <joe@example.com>"
        git push quagga archive/foo

presuming ‘quagga’ corresponds to a file in your .git/remotes with
configuration for the appropriate Quagga.net repository.

USEFUL URLs
===========

* David Lamparter <equinox@diac24.net> runs a patchwork instance at
  <http://patchwork.quagga.net/project/quagga/list/>

