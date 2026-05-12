
.PHONY: main.pdf clean

main.pdf:
	latexmk -pdf -halt-on-error main

c:
	latexmk -pdf -pvc main

clean:
	latexmk -C main
