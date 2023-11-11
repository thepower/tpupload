nginx = openresty

md2html = ./util/fmtMd.js
md2text = pandoc --from markdown_github-hard_line_breaks --to plain

md_files := $(wildcard en/*.md cn/*.md) $(patsubst %.md.tt2,%.md,$(wildcard en/*.md.tt2 cn/*.md.tt2))
html_files := $(patsubst %.md,html/%.html,$(md_files))
txt_files := $(patsubst %.md,text/%.txt,$(md_files))

i18n_lua = lua/openresty_org/i18n.lua
templates_lua = lua/openresty_org/templates.lua

lua_files := $(sort $(filter-out $(i18n_lua) $(templates_lua),$(wildcard lua/*.lua lua/openresty_org/*.lua)))
auto_tt2_files := templates/posts-slide-cn.tt2 templates/posts-slide-en.tt2
tt2_files := $(sort $(wildcard templates/*.tt2)) $(auto_tt2_files)

less_file = css/main.less
css_file = $(patsubst %.less, %.css, $(less_file))

extract_pl = ./util/extract.pl
gendata_pl = ./util/gen-data.pl
msginit_pl = ./util/msginit.pl
msgfmt_pl = ./util/msgfmt.pl

po_files = po/cn.po
tsv_files = posts-en.tsv posts-cn.tsv
tpage = tpage

.PRECIOUS: $(md_files)
.DELETE_ON_ERRORS: $(templates_lua) $(patsubst %.md.tt2,%.md,$(wildcard en/*.md.tt2)) $(patsubst %.md.tt2,%.md,$(wildcard cn/*.md.tt2))

.PHONY: all
all: templates css msgfmt

$(auto_tt2_files):
	./util/gen-templates.js

.PHONY: check
check:
	@echo $(md_files)

.PHONY: auto-templates
auto-templates: $(auto_tt2_files)

.PHONY: templates
templates: $(templates_lua)

$(templates_lua): $(tt2_files)
	lemplate --compile $^ > $@

.PHONY: css
css: $(css_file)
$(css_file): $(less_file)
	lessc $^ $@

.PHONY: run
run:
	mkdir -p logs
	$(nginx) -p $$PWD -c conf/nginx.conf

reload: logs/nginx.pid
	$(nginx) -p $$PWD -c conf/nginx.conf -t
	kill -HUP `cat $<`

stop: logs/nginx.pid
	$(nginx) -p $$PWD -c conf/nginx.conf -t
	kill -QUIT `cat $<`

.PHONY: clean
clean:
	rm -f templates/posts-slide-*.tt2
	rm -rf html text *.tsv
	rm -f $(templates_lua)

.PHONY: html
html: $(html_files)

html/%.html: %.md
	@mkdir -p html/en html/cn
	$(md2html) $< > $@

.PHONY: text
text: $(txt_files)

text/%.txt: %.md
	mkdir -p text/en text/cn
	$(md2text) $< --output $@

%.md: %.md.tt2
	$(tpage) $< > $@

# WARNING: this target will override existing .md files
# so any manual edits would get lost!
.PHONY: extract
extract:
	$(extract_pl) ../v1/index.html en
	$(extract_pl) ../v1/cn/index.html cn

.PHONY: gendata
gendata: $(tsv_files)

$(tsv_files): $(html_files) $(txt_files) $(gendata_pl)
	$(gendata_pl) en
	$(gendata_pl) cn

.PHONY: initdb
initdb: $(tsv_files)
	psql -Uopenresty openresty_org -v "ON_ERROR_STOP=1" -f init.sql

.PHONY: deploy
deploy:
	ls $(tsv_files)
	psql -Uopenresty openresty_org -v "ON_ERROR_STOP=1" -f init.sql

.PHONY: msginit
msginit: $(po_files)

$(po_files): $(lua_files) $(tt2_files) $(msginit_pl)
	$(msginit_pl) --outdir po --locale cn $(lua_files) $(tt2_files)

.PHONY: msgfmt
msgfmt: $(i18n_lua)

$(i18n_lua): $(po_files) $(msgfmt_pl)
	$(msgfmt_pl) -o $(i18n_lua) $(po_files)
