# Contributing to ESAPI -- Details

## Getting Started
If you have not already done so, go back and read the section
"[Contributing to ESAPI legacy](https://github.com/ESAPI/esapi-java-legacy/blob/develop/README.md#contributing-to-esapi-legacy)" in ESAPI's README.md file. It
may contain updates and advice not contained herein.

### A Special Note on GitHub Authentication
GitHub has announced that they are deprecating password based authentication
using username / password and beginning 2021-08-13, you will no longer be
able to your password to authenticate to 'git' operations on GitHub.com.
Please see https://github.blog/2020-12-15-token-authentication-requirements-for-git-operations/
for details and plan accordingly.

### A Special Note Regarding Making Commits for PRs
Shortly after the 2.5.1.0 ESAPI release in late November 2022, the ESAPI
team decided to lock down the 'develop' amd 'main' branches. Merges from
PRs are done to the 'develop' branch. That means that if you intend to
contribute to ESAPI, you must be signing your commits. Please see the
GitHub instructions at
        https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits
for details.

### Git Branching Model
We are following the branching model described in
        https://nvie.com/posts/a-successful-git-branching-model
If you are unfamiliar with it, you would be advised to give it a quick
perusal. The major point is that the 'main' (formerly 'master') branch is
reserved for official releases (which will be tagged), the 'develop' branch
is used for ongoing development work and is the default branch, and we
generally work off 'issue' branches named 'issue-#' where # is the GitHub
issue number. (The last is not an absolute requirement, but rather a
suggested approach.)

Finally, we recommend setting the git property 'core.autocrlf' to 'input'
in your $HOME/.gitconfig file; e.g., that file should contain something
like this:

    [core]
        autocrlf = input


### Required Software
We use Maven for building. Maven 3.6.3 or later is required. You also need
JDK 8 or later. [Note: If you use JDK 9 or later, there will be multiple
failures when you try to run 'mvn test' as well as some general warnings.
See [ESAPI GitHub issue #496](https://github.com/ESAPI/esapi-java-legacy/issues/496) for details. We welcome volunteers to address
this.]
## Finding Something Interesting to Work on

See the section [Contributing to ESAPI Legacy](https://github.com/ESAPI/esapi-java-legacy/blob/develop/README.md#contributing-to-esapi-legacy)
in the ESAPI README for suggestions. While you don't *have* to work on something labeled "good first issue"
or "help wanted", those are good places to start for someone not yet familiar with the ESAPI code base.

You will need a account on GitHub though. Once you create one, let us know
what it is. Then if you want to work on a particular issue, we can assign
it to you so someone else won't take it.

If you have questions, email Kevin Wall (Kevin.W.Wall@gmail.com) or Matt
Seil (xeno6696@gmail.com).


## Building ESAPI
See our local GitHub wiki page, [Building ESAPI](https://github.com/ESAPI/esapi-java-legacy/wiki/Building-ESAPI),
which briefly discusses how to build ESAPI via Maven.

You can also refer to [Using ESAPI for Java with Eclipse](https://github.com/ESAPI/esapi-java-legacy/wiki/Using-ESAPI-for-Java-with-Eclipse)
if you prefer working from IDEs. There is also a much older ESAPI wiki page,
[Building with Eclipse](https://www.owasp.org/index.php/ESAPI-BuildingWithEclipse)
that might be useful.

As always, any contributions to ESAPI's admittedly skimpy documentation in this area is welcome.
In particular, contributing some hints about debugging applications using ESAPI
would be very useful to our ESAPI clients.

## Steps to work with ESAPI
I usually do everything from the bash command prompt in Linux Mint,
but other people use Windows. If you prefer an IDE, I can't help you
much, but I can help with at least modest problems. If you have more
difficult problems, I will probably refer you to my project co-leader,
Matt who groks git a lot better than I.

But the basic high level steps are:

1. Fork https://github.com/ESAPI/esapi-java-legacy to your own GitHub repository using the GitHub web site.
2. On your local laptop, clone your own GitHub ESAPI repo (i.e, the forked repo created in previous step)
3. Create a new branch to work on an issue. I usually name the branch 'issue-#' where '#' is the GitHub issue # is will be working on, but you can call it whatever. E.g.,
   ```bash
        $ git checkout -b issue-#
   ```
4. Work on the GitHub issue on this newly created issue-# branch. Be sure that you also create new JUnit tests as required that confirm that the issue is corrected, or if you are introducing new functionality, ensure
   that functionality is sufficiently covered.
5. Make sure everything builds correctly and all the JUnit tests pass ('mvn test'). [Note: There are some known issues with test failures if your are running under Windows and your local ESAPI Git repo located anywhere other than the C: drive, where the test `ValidatorTest.testIsValidDirectoryPath()` fails. 
6. If you have added any dependencies, please also run OWASP Dependency-Check and look at the generated report left in 'target/dependency-check-report.html' to make sure there were not any CVEs introduced. (Alternately you can run 'mvn verify' which will first run the tests and then run Dependency-Check.) Note if this is the first time you have run Dependency-Check for ESAPI, expect it to take a while (often 30 minutes or so!). To execute Dependency Check from Maven, run:
   ```bash
        $ mvn org.owasp:dependency-check-maven:check
   ```
7. Commit your changes locally.
8. Push your 'issue-#' branch to your personal, forked ESAPI GitHub repo. E.g.,
   ```bash
        $ git checkout issue-444
        $ git remote -v | grep origin       # Confirm 'origin' refers to YOUR PERSONAL GitHub repo
        $ git push origin issue-444         # Push the committed changes on the 'issue-444' branch
   ```
9. Go to your personal, forked ESAPI GitHub repo (web interface) and create a 'Pull Request' (PR) from your 'issue-#' branch.
10. Back on your local personal laptop / desktop, merge your issue branch with your local 'develop' branch. I.e.,
        $ git checkout develop
        $ git merge issue-444
11. Do not remove your branch on your forked repository until your PR from your branch has been merged into the ESAPI/esapi-java/legacy 'develop' branch.
   Note at least one the 3 main contributors on will review your commits before
   merging them and they may do a formal code review and request further changes.
   Once they are satisfied, they will merge your PR.

In theory, you can do all this 'git' magic from Eclipse and presumably other
IDEs like Oracle NetBeans or JetBrains IntelliJ IDEA. From Eclipse, it is right-click
on the project and then select 'Team' to do the commits, etc. If you choose that
route, you're pretty much on your own because none of us use that for Git
interactions.
