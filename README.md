# APKSNEEZE Lab


run app
docker-compose -f local.yml
or as daemon
docker-compose -f local.yml -d


compile yara rules
docker-compose -f local.yml exec flask flask apksneeze compile

seed db (populate grep patterns)
docker-compose -f local.yml exec flask flask apksneeze seed

