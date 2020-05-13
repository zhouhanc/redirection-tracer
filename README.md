# redirection-tracer
System to trace websites that redirect

Here is a list of important files and their functionalities
1. `headless_crawler.py` is the main script to collect redirected URLs
2. `viz_redirection_chain.ipynb` generates redirection graphs
3. `IP_location_visualization.ipynb` generates geo-location maps
4. folder `seed_files` contain a list of fake news sources


Redirection Tracer works in the following steps

1. Identify seed domains that redirect
2. Search domains co-hosted on the same IP(s) as domains in #1
3. Collect redirection paths of domains in #2, and cluster domains that share common path 

Redirection Tracer offers following visualizations

1. Redirection chain
2. IP geo-location distribution
3. Histogram of WHOIS record, DNS record