from django.core.management.base import BaseCommand, CommandError
import subprocess
import csv
import os 
import tempfile

from scans.models import Domain, SSLResult, PSHTTResult

class Command(BaseCommand):
	help = 'Run the scanner'

	def handle(self, *args, **options):
		path_to_scanner = "./domain-scan-master/scan"
		scanners = "--scan=sslyze,pshtt"


		tmpCSV = tempfile.NamedTemporaryFile(mode="w",  suffix=".csv", delete=False)
		self.stdout.write("Temp CSV = " + tmpCSV.name)
		writer = csv.writer(tmpCSV)
			
		domains = Domain.objects.all()
		for domain in domains:
			writer.writerow([str(domain.name), ])
		
		tmpCSV.close()	
		s = subprocess.run(args=[path_to_scanner, scanners, tmpCSV.name])

		self.stdout.write("back again")
		self.stdout.write(str(s))

		os.remove(tmpCSV.name)


		with open('results/sslyze.csv') as f:
			inputfile = csv.DictReader(f)
			for row in inputfile:
				self.stdout.write("PROCESSING")
				self.stdout.write(str(row["Domain"]))
				if row["Errors"] != "":
					self.stdout.write("ERRORS " + str(row["Errors"]))
					continue
	
				d = Domain.objects.get(name=row["Domain"])
				obj, created = SSLResult.objects.update_or_create(domain=d, 
					defaults={'SSLv2':row["SSLv2"],
						  'SSLv3':row["SSLv3"],
						  'TLSv10': row["TLSv1.0"],
						  'TLSv11': row["TLSv1.1"],
						  'TLSv12': row["TLSv1.2"],
						  'PFS': row["Any Forward Secrecy"],
						  'AFS': row["All Forward Secrecy"],
						  'DHGroup': row["Weakest DH Group Size"],
						  'anyRC4': row["Any RC4"],
						  'allRC4': row["All RC4"],
						  'tripleDES': row["Any 3DES"],
						  'keyType': row["Key Type"],
						  'keyLength': row["Key Length"],
						  'sigAlgo': row["Signature Algorithm"],
						  'shaServed': row["SHA-1 in Served Chain"],
						  'shaConstructed': row["SHA-1 in Constructed Chain"],
						  'notBefore': row["Not Before"],
						  'notAfter': row["Not After"],
						  'highestServedIssuer': row["Highest Served Issuer"],
						  'highestConstructedIssuer': row["Highest Constructed Issuer"], })



		self.stdout.write("")

		with open('results/pshtt.csv') as f:
			inputfile = csv.DictReader(f)
			for row in inputfile:
				self.stdout.write("PSHTT PROCESSING")
				self.stdout.write(str(row["Domain"]))
				if row["Unknown Error"] == "True":
					self.stdout.write("ERRORS " + str(row["Unknown Error"]))
					continue
				d = Domain.objects.get(name=row["Domain"])

				self.stdout.write("looking for = " + str(d))

				obj, created = PSHTTResult.objects.update_or_create(domain=d, 
					defaults={'redirect':row["Redirect"],	
						  'validHTTPS': row["Valid HTTPS"],
						  'defaultHTTPS': row["Defaults to HTTPS"],
						  'downgradeHTTPS': row["Downgrades HTTPS"],
						  'strictlyHTTPS': row["Strictly Forces HTTPS"],
						  'badChain': row["HTTPS Bad Chain"],
						  'badHostname': row["HTTPS Bad Hostname"],
						  'expiredCert': row["HTTPS Expired Cert"],
						  'selfSignedCert': row["HTTPS Self Signed Cert"],
						  'HSTS': row["HSTS"],
						  'supportHTTPS': row["Domain Supports HTTPS"],
						  'enforceHTTPS': row["Domain Enforces HTTPS"],
						  'strongHSTS': row["Domain Uses Strong HSTS"],
						})

# Domain,Base Domain,Canonical URL,Live,Redirect,Redirect To,Valid HTTPS,Defaults to HTTPS,Downgrades HTTPS,Strictly Forces HTTPS,HTTPS Bad Chain,HTTPS Bad Hostname,HTTPS Expired Cert,HTTPS Self Signed Cert,HSTS,HSTS Header,HSTS Max Age,HSTS Entire Domain,HSTS Preload Ready,HSTS Preload Pending,HSTS Preloaded,Base Domain HSTS Preloaded,Domain Supports HTTPS,Domain Enforces HTTPS,Domain Uses Strong HSTS,Unknown Error


