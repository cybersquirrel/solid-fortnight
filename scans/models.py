from django.db import models
from django.utils import timezone

# Create your models here.



class Domain(models.Model):
	name = models.CharField(max_length=500)

	def latest_SSL(self):
		s = self.sslresult_set.all()
		if len(s) > 0:
			return s[0] 		# hack to allow ordering in the future
		else:
			return None

	def latest_PSHTT(self):
		s = self.pshttresult_set.all()
		if len(s) > 0:
			return s[0] 		# hack to allow ordering in the future
		else:
			return None

	def __str__(self):
		return str(self.name)

# Domain,Base Domain,Scanned Hostname,SSLv2,SSLv3,TLSv1.0,TLSv1.1,TLSv1.2,Any Forward Secrecy,All Forward Secrecy,Weakest DH Group Size,Any RC4,All RC4,Any 3DES,Key Type,Key Length,Signature Algorithm,SHA-1 in Served Chain,SHA-1 in Constructed Chain,Not Before,Not After,Highest Served Issuer,Highest Constructed Issuer,Errors

class SSLResult(models.Model):
	domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
	SSLv2 = models.BooleanField("SSLv2")
	SSLv3 = models.BooleanField("SSLv3")
	TLSv10 = models.BooleanField("TLSv1.0")
	TLSv11 = models.BooleanField("TLSv1.1")
	TLSv12 = models.BooleanField("TLSv1.2")
	PFS = models.BooleanField("Any Forward Secrecy")
	AFS = models.BooleanField("All Forward Secrecy")
	DHGroup = models.CharField("Weakest DH Group Size", max_length=500)
	anyRC4 = models.BooleanField("Any RC4")
	allRC4 = models.BooleanField("All RC4")
	tripleDES = models.BooleanField("Any 3DES")
	keyType = models.CharField("Key Type", max_length=500)
	keyLength = models.CharField("Key Length", max_length=500)
	sigAlgo = models.CharField("Signature Algorithm", max_length=500)
	shaServed = models.BooleanField("SHA-1 in Served Chain")
	shaConstructed = models.BooleanField("SHA-1 in Constructed Chain")
	notBefore = models.DateTimeField("Not Before")
	notAfter = models.DateTimeField("Not After")
	highestServedIssuer = models.CharField("Highest Served Issuer", max_length=500)
	highestConstructedIssuer = models.CharField("Highest Constructed Issuer", max_length=500)

	def __str__(self):
		return str("SSL scan for " + str(self.domain))

	def legacyProtocol(self):
		return (self.SSLv2 or self.SSLv3)
	
	def cert_time_left(self):
		now = timezone.now()
		timeleft = self.notAfter - now
		return timeleft.days



class PSHTTResult(models.Model):
	domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
	redirect = models.BooleanField("Redirect")
	validHTTPS = models.BooleanField("Valid HTTPS")
	defaultHTTPS = models.BooleanField("Default HTTPS")
	downgradeHTTPS = models.BooleanField("Downgrades HTTPS")
	strictlyHTTPS = models.BooleanField("Strictly Forces HTTPS")
	badChain = models.BooleanField("Bad Chain")
	badHostname = models.BooleanField("Bad Hostname")
	expiredCert = models.BooleanField("Expired Cert")
	selfSignedCert = models.BooleanField("Self-signed Cert")
	HSTS = models.BooleanField("HSTS")
	supportHTTPS = models.BooleanField("Support HTTPS")
	enforceHTTPS = models.BooleanField("Enforce HTTPS")
	strongHSTS = models.BooleanField("Strong HSTS")

	def __str__(self):
		return str("PSHTT scan for " + str(self.domain))


	def HTTPS_problems(self):
		return (self.downgradeHTTPS or self.badChain or self.badHostname or self.expiredCert or self.selfSignedCert)


# Domain,Base Domain,Canonical URL,Live,Redirect,Redirect To,Valid HTTPS,Defaults to HTTPS,Downgrades HTTPS,Strictly Forces HTTPS,HTTPS Bad Chain,HTTPS Bad Hostname,HTTPS Expired Cert,HTTPS Self Signed Cert,HSTS,HSTS Header,HSTS Max Age,HSTS Entire Domain,HSTS Preload Ready,HSTS Preload Pending,HSTS Preloaded,Base Domain HSTS Preloaded,Domain Supports HTTPS,Domain Enforces HTTPS,Domain Uses Strong HSTS,Unknown Error
