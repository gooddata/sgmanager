# This makefile is supposed to be used only from git repo
ifeq ($(wildcard .git),)
$(error This makefile works only from git repository)
endif

$(shell git diff --quiet)
ifneq ($(.SHELLSTATUS),0)
#$(error git repository is dirty, fix this first! $(shell git diff))
endif
PYTHON ?= python3
VERSION = $(shell $(PYTHON) -c "import sgmanager; print(sgmanager.__version__)")
REVNUM = $(shell git rev-list --count HEAD)
COMMIT = $(shell git rev-parse HEAD)
SHORTCOMMIT = $(shell git rev-parse --short HEAD)

TARBALL = sgmanager-$(VERSION)~git+$(REVNUM).$(SHORTCOMMIT).tar.gz

sgmanager.spec: .FORCE
	sed \
		-e "s|@VERSION@|$(VERSION)|" \
		-e "s|@REVNUM@|$(REVNUM)|" \
		-e "s|@COMMIT@|$(COMMIT)|" \
		-e "s|@SHORTCOMMIT@|$(SHORTCOMMIT)|" \
		sgmanager.spec.in > sgmanager.spec

tarball:
	git archive --prefix=sgmanager-$(COMMIT)/ --format=tar.gz $(COMMIT) -o $(TARBALL)

srpm: sgmanager.spec tarball
	rpmbuild -bs sgmanager.spec -D "_sourcedir $(PWD)" -D "_srcrpmdir $(PWD)/srpm"

.FORCE:
.DEFAULT_GOAL := srpm
.PHONY: tarball srpm
