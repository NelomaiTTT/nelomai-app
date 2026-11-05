package ru.nelomai.testing

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.security.KeyFactory
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Collections
import javax.net.SocketFactory
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SNIHostName
import javax.net.ssl.SNIMatcher
import javax.net.ssl.SNIServerName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockWebServer
import ru.nelomai.runtime.v1.PanelDns

/** Real TLS with public test keys; only TCP destination and trust roots are local. */
class PanelTlsFixture(backupCertificate: Boolean = true, private val trustFixtures: Boolean = true) : AutoCloseable {
    val server = MockWebServer()
    val destinations: MutableList<String> = Collections.synchronizedList(mutableListOf())
    val serverNames: MutableList<String> = Collections.synchronizedList(mutableListOf())
    private val trust: X509TrustManager
    private val clientTls: SSLContext

    init {
        val prefix = if (backupCertificate) "backup-" else ""
        val leaf = certificate(prefix + "server.der")
        val key = KeyFactory.getInstance(leaf.publicKey.algorithm).generatePrivate(PKCS8EncodedKeySpec(bytes(prefix + "server-key.der")))
        val keys = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            setKeyEntry("test", key, "test".toCharArray(), arrayOf(leaf, certificate(prefix + "ca.der")))
        }
        val managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(keys, "test".toCharArray()) }
        val tls = SSLContext.getInstance("TLS").apply { init(managers.keyManagers, null, null) }
        val delegate = tls.socketFactory
        fun capture(socket: Socket): Socket = (socket as SSLSocket).apply {
            sslParameters = sslParameters.apply { sniMatchers = listOf(object : SNIMatcher(0) {
                override fun matches(name: SNIServerName): Boolean {
                    this@PanelTlsFixture.serverNames.add((name as SNIHostName).asciiName)
                    return true
                }
            }) }
        }
        server.useHttps(object : SSLSocketFactory() {
            override fun getDefaultCipherSuites() = delegate.defaultCipherSuites
            override fun getSupportedCipherSuites() = delegate.supportedCipherSuites
            override fun createSocket(socket: Socket, host: String, port: Int, autoClose: Boolean) = capture(delegate.createSocket(socket, host, port, autoClose))
            override fun createSocket(host: String, port: Int) = capture(delegate.createSocket(host, port))
            override fun createSocket(host: String, port: Int, local: InetAddress, localPort: Int) = capture(delegate.createSocket(host, port, local, localPort))
            override fun createSocket(host: InetAddress, port: Int) = capture(delegate.createSocket(host, port))
            override fun createSocket(host: InetAddress, port: Int, local: InetAddress, localPort: Int) = capture(delegate.createSocket(host, port, local, localPort))
        }, false)
        server.start(InetAddress.getByName("127.0.0.1"), 0)
        val roots = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null); setCertificateEntry("ru", certificate("ca.der")); setCertificateEntry("top", certificate("backup-ca.der"))
        }
        trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(roots) }
            .trustManagers.filterIsInstance<X509TrustManager>().single()
        clientTls = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), null) }
    }

    fun client(base: OkHttpClient, dns: PanelDns): OkHttpClient = base.newBuilder()
        .dns(object : okhttp3.Dns { override fun lookup(hostname: String) = dns.lookup(hostname) })
        .socketFactory(object : SocketFactory() {
            override fun createSocket() = object : Socket() {
                override fun connect(endpoint: SocketAddress, timeout: Int) {
                    destinations += (endpoint as InetSocketAddress).address.hostAddress
                    super.connect(InetSocketAddress("127.0.0.1", server.port), timeout)
                }
            }
            override fun createSocket(host: String, port: Int): Socket = error("expected unconnected socket")
            override fun createSocket(host: String, port: Int, local: InetAddress, localPort: Int): Socket = error("expected unconnected socket")
            override fun createSocket(host: InetAddress, port: Int): Socket = error("expected unconnected socket")
            override fun createSocket(host: InetAddress, port: Int, local: InetAddress, localPort: Int): Socket = error("expected unconnected socket")
        })
        .connectTimeout(2, java.util.concurrent.TimeUnit.SECONDS)
        .readTimeout(2, java.util.concurrent.TimeUnit.SECONDS)
        .apply { if (trustFixtures) sslSocketFactory(clientTls.socketFactory, trust) }
        .build()

    override fun close() = server.shutdown()
    private fun bytes(name: String): ByteArray = requireNotNull(javaClass.classLoader!!.getResourceAsStream(name)) { name }.use { it.readBytes() }
    private fun certificate(name: String) = CertificateFactory.getInstance("X.509").generateCertificate(bytes(name).inputStream()) as X509Certificate
}
