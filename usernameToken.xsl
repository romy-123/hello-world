<?xml version="1.0" encoding="UTF-8"?>

<!-- Autores: IBM 
    IBM - Global Business Services - GBS Colombia 2019 
	Objetivo: Añadir cabecera UsernameToken validando si hay cabeceras previas. 
	Cambios: MMM-DD-AAAA 
	 -->

<xsl:stylesheet version="1.0"
	xmlns:soapenv		=	"http://schemas.xmlsoap.org/soap/envelope/"
	xmlns:soapenv10		=	"http://schemas.xmlsoap.org/soap/envelope"
	xmlns:soapenv12		=	"http://www.w3.org/2003/05/soap-envelope"
	xmlns:soapenv121	=	"http://www.w3.org/2003/05/soap-envelope/" 
	xmlns:xsl			=	"http://www.w3.org/1999/XSL/Transform"
	xmlns:wsa			=	"http://schemas.xmlsoap.org/ws/2004/08/addressing"
	xmlns:wsu			=	"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	xmlns:wsse			=	"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	xmlns:dp			=	"http://www.datapower.com/extensions"
	xmlns:dpquery			=	"http://www.datapower.com/param/query"
	xmlns:date			=	"http://exslt.org/dates-and-times"
	extension-element-prefixes="dp date" 
	exclude-result-prefixes="dp soapenv soapenv10 soapenv12 soapenv121 date">

	<xsl:output indent="yes" method="xml" omit-xml-declaration="yes" />

	<!-- Variables globales -->
	 <xsl:param name="dpquery:USERNAME" select="'andres1'"/>
     <xsl:param name="dpquery:PASSWORD" select="'1235'"/>
    
	
	<xsl:variable name="clientUri" select="dp:variable('var://service/URI')" />
	
	<!-- Variables de tiempo -->
	<xsl:variable name="timestamp" select="date:date-time()"/> 
	<xsl:variable name="ZuluTimeCre" select="date:add($timestamp,'PT0H')"/>
	<xsl:variable name="ms" select="substring(dp:time-value(),11,3)"/>
	
	<!-- Calcula los datos necesarios -->
	<xsl:variable name="UUID" select="dp:generate-uuid()"/>
	<xsl:variable name="Nonce" select="dp:random-bytes(16)"/>
	<xsl:variable name="WSSECreated"><xsl:value-of select="concat(substring($ZuluTimeCre,1,19),'.',$ms,'Z')"/></xsl:variable>
	<xsl:variable name="SAction" select="string(dp:http-request-header('SOAPAction'))"/>

	<xsl:variable name="username">
		<!-- <xsl:variable name="value" select="$wsrrdoc/resources/resource/properties[property/@name='location' and property/@value=$prop]/property[@name='username']/@value" />-->
		<dp:set-variable name="'var://context/test'" value="$dpquery:USERNAME" />
		<xsl:variable name="value" select="'Andres'"/>
		<xsl:choose>
			<xsl:when test="$value != ''">
				<xsl:value-of select="$value" />
			</xsl:when>
			<xsl:otherwise>
				<dp:reject>
					The service
					<xsl:value-of select="$clientUri" />
					requires UsernameToken <xsl:value-of select="$value" /> Injection but no user has been specified.
					Please set the username property.
				</dp:reject>
			</xsl:otherwise>
		</xsl:choose>
	</xsl:variable>

	<xsl:variable name="password">
		<!-- <xsl:variable name="value"
			select="$wsrrdoc/resources/resource/properties[property/@name='location' and property/@value=$prop]/property[@name='password']/@value" />-->
			<!-- <xsl:variable name="value" value="$dpquery:PASSWORD"/>-->
		<xsl:variable name="value" select="'123'"/>
		<xsl:choose>
			<xsl:when test="$value != ''">
				<xsl:value-of select="$value" />
			</xsl:when>
			<xsl:otherwise>
				<dp:reject>
					The service
					<xsl:value-of select="$clientUri" />
					requires UsernameToken Injection but no password has been
					specified. Please set the password property.
				</dp:reject>
			</xsl:otherwise>
		</xsl:choose>
	</xsl:variable>
	
	
	<!-- Plantilla que se aplica cuando el namespace es: xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" -->
	<xsl:template match="soapenv:Envelope">
	
		<xsl:choose>
			<!-- Valida que el Header no esté presente ó que el Header esté vacío -->
			<xsl:when test="not(*[local-name()='Header']) or *[local-name()='Header'] = ''">
				<xsl:copy>
					<soapenv:Header>
						<wsse:Security>
							<wsse:UsernameToken xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
												xmlns:wssu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
								                xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
									<wsse:Username>
										<xsl:value-of select="$username" />
									</wsse:Username>
									<wsse:Password>
										<xsl:attribute name="Type">
											<xsl:value-of select="'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText'" />
										</xsl:attribute>
										<xsl:value-of select="$password" />
									</wsse:Password>
									<wsse:Nonce>
											<xsl:attribute name="EncodingType">
												<xsl:value-of select="'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary'" />
											</xsl:attribute>
											<xsl:value-of select="$Nonce"/>
									</wsse:Nonce>
									<wssu:Created>
										<xsl:value-of select="$WSSECreated"/>
									</wssu:Created>
							</wsse:UsernameToken>
						</wsse:Security>
					</soapenv:Header>
					<xsl:copy-of select="/soapenv:Envelope/soapenv:Body" />
				</xsl:copy>
			</xsl:when>
			<xsl:otherwise>
				<!-- Si el Header está presente se valida que no contenga ninguna cabecera de Seguridad -->
				<xsl:choose>
					<xsl:when test="not(soapenv:Header/*[local-name()='Security'])">
						<xsl:copy>
							<soapenv:Header>
								<xsl:copy-of select="/soapenv:Envelope/soapenv:Header/node()" />
								<wsse:Security>
									<wsse:UsernameToken xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
												xmlns:wssu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
								                xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
										<wsse:Username>
											<xsl:value-of select="$username" />
										</wsse:Username>
										<wsse:Password>
											<xsl:attribute name="Type">
													<xsl:value-of select="'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText'" />
												</xsl:attribute>
											<xsl:value-of select="$password" />
										</wsse:Password>
										
										<wsse:Nonce>
												<xsl:attribute name="EncodingType">
													<xsl:value-of select="'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary'" />
												</xsl:attribute>
												<xsl:value-of select="$Nonce"/>
										</wsse:Nonce>
										<wssu:Created>
												<xsl:value-of select="$WSSECreated"/>
										</wssu:Created>
									</wsse:UsernameToken>
								</wsse:Security>
							</soapenv:Header>
							<xsl:copy-of select="/soapenv:Envelope/soapenv:Body" />
						</xsl:copy>
					</xsl:when>
					<xsl:otherwise>
						<!-- Si contiene alguna cabecera de seguridad se verifica que el mensaje no tenga previamente un UsernameToken -->
						<xsl:choose>
							<xsl:when test="not(soapenv:Header/wsse:Security/*[local-name()='UsernameToken'])">
								
								<xsl:variable name="header_no_security" select="/soapenv:Envelope/soapenv:Header/node()"/>
								
								<xsl:variable name="header_no_security_2">
									<dp:serialize select="$header_no_security" omit-xml-decl="yes"/>
								</xsl:variable>

								<xsl:variable name="sub1" select="substring-after($header_no_security_2,'&lt;/wsse:Security&gt;')" />
								<xsl:variable name="sub2" select="substring-before($header_no_security_2,'&lt;wsse:Security')" />
								<xsl:copy>
									<soapenv:Header>
										<wsse:Security>
											<xsl:copy-of select="/soapenv:Envelope/soapenv:Header/wsse:Security/node()" />
											<wsse:UsernameToken xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
																xmlns:wssu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
								                				xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
												<wsse:Username>
													<xsl:value-of select="$username" />
												</wsse:Username>
												<wsse:Password>
													<xsl:attribute name="Type">
															<xsl:value-of select="'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText'" />
														</xsl:attribute>
													<xsl:value-of select="$password" />
												</wsse:Password>
												<wsse:Nonce>
														<xsl:attribute name="EncodingType">
															<xsl:value-of select="'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary'" />
														</xsl:attribute>
														<xsl:value-of select="$Nonce"/>
												</wsse:Nonce>
												<wssu:Created>
														<xsl:value-of select="$WSSECreated"/>
											    </wssu:Created>
											</wsse:UsernameToken>
										</wsse:Security>
										
										<xsl:choose>
											<xsl:when test="contains($sub1,'&lt;')">
												<xsl:copy-of select="dp:parse($sub1)" />
											</xsl:when>
										</xsl:choose>
										
										<xsl:choose>
											<xsl:when test="contains($sub2,'&lt;')">
												<xsl:copy-of select="dp:parse($sub2)" />
											</xsl:when>
										</xsl:choose>
									</soapenv:Header>
									<xsl:copy-of select="/soapenv:Envelope/soapenv:Body" />
								</xsl:copy>
							</xsl:when>
							<xsl:otherwise>
								<!-- En caso que contenga una cabecera UsernameToken el mensaje no se modifica y pasa tal cual llega desde el Frontend -->
								<xsl:copy-of select="." />
							</xsl:otherwise>
						</xsl:choose>
					</xsl:otherwise>
				</xsl:choose>
			</xsl:otherwise>
		</xsl:choose>
	</xsl:template>

</xsl:stylesheet>