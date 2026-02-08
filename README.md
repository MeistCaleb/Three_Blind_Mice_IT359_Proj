# Three Blind Mice IT359 Project

## Team Members
- Caleb Meister
- Nathan Sigulas
- Ryan Garland

## Project Overview
###An Automated IP Scanner.
This will be a tool that analyzes IP addresses and determines their security risk level. It pulls data from public blacklists, geolocation databases, and reputation services to produce a risk score and classification (e.g., Safe, Suspicious, Malicious). The goal is to help security teams quickly triage IP addresses during investigations or monitoring.

## Full Project Idea
- An Automated IP Scanner.
  - It will commit an Nmap/Masscan scans to determine what ports are open. 
  - It will alos pull from blacklists, geolocations, and reputation scores to determine the risk of a certain IP.
  - All of this to help determine where a target is located, how it is vulnerable and if it has been used in any attacks before.


### Core Features
- Input an IP
- Pull from:
	- Blacklists
	- Geolocation
	- Reputation Scores
- Return: 
	- Risk Score
	- Classification Label 
	- Some information about the IP
	- An explanation on why the IP was flagged

### How AI will be used
- It will help combine the data being pulled and put it into a single risk score.
- Help detect patterns.
- Summarize why the IP was flagged.

### Expected Results
- A working tool that:
	- Accepts an IP address 
	- Queries multiple threat intelligence sources
	- Produces a risk score and classification
	- Generates Ai-assisted explanations
- With the documentation on how we got it to work

  
