#docker build -t sspamm3 .
docker run --rm -it \
	-v $(pwd)/sspamm3.py:/app/sspamm3.py \
	-v $(pwd)/sspamm3.conf.example:/app/sspamm3.conf \
	-v $(pwd)/sspamm3.json.example:/app/example.json \
	--name sspamm3-test sspamm3 \
	python3 sspamm3.py --test /app/example.json
