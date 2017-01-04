ci:
	curl -sSLo golang.sh https://raw.githubusercontent.com/Luzifer/github-publish/master/golang.sh
	bash golang.sh


test:
	gometalinter --deadline 20s --cyclo-over=15
