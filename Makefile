.PHONY: install up down scan logs

install:
	./install.sh

up:
	docker compose up -d

down:
	docker compose down

scan:
	docker compose run --rm scanner oscap

logs:
	docker compose logs -f
