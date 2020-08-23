./: { libcornet/ examples/ mem_writer/ tests/ benchmarks/ helpers/ } manifest

#./: doc{*}: backlink = false
#exe{*}@./: backlink = false
#exe{**}: backlink = false

tests/:    install = false
examples/: install = false
helpers/:  install = false
