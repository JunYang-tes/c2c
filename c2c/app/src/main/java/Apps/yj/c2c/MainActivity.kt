package Apps.yj.c2c

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.TextField
import androidx.compose.ui.unit.dp
import Apps.yj.c2c.ui.theme.C2cTheme
import android.app.Activity
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NdefMessage
import android.nfc.NdefRecord
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.Ndef
import android.util.Log
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import arrow.core.Either
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and

class MainActivity : ComponentActivity() {
    val broadcaster = UdpBroadcaster(this)
    private var portText by mutableStateOf("")
    private var pairCodeText by mutableStateOf("")
    private var nfcAdapter: NfcAdapter? = null
    
    private fun saveValues() {
        val sharedPref = getSharedPreferences("C2CPrefs", Context.MODE_PRIVATE)
        with(sharedPref.edit()) {
            putString("port_text", portText)
            putString("pair_code_text", pairCodeText)
            apply()
        }
    }
    
    private fun loadValues() {
        val sharedPref = getSharedPreferences("C2CPrefs", Context.MODE_PRIVATE)
        portText = sharedPref.getString("port_text", "") ?: ""
        pairCodeText = sharedPref.getString("pair_code_text", "") ?: ""
    }
    
    private fun writeNfcTag(intent: Intent) {
        val tag = intent.getParcelableExtra<Tag>(NfcAdapter.EXTRA_TAG)
        if (tag != null) {
            try {
                val ndef = Ndef.get(tag)
                if (ndef != null) {
                    // Create the NdefMessage with both text record and application record
                    val message = NdefMessage(
                        arrayOf(
                            NdefRecord.createTextRecord(null, "$portText|$pairCodeText"),
                            NdefRecord.createApplicationRecord("Apps.yj.c2c")
                        )
                    )
                    
                    ndef.connect()
                    ndef.writeNdefMessage(message)
                    ndef.close()
                    Toast.makeText(this, "Successfully wrote to NFC tag", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, "Tag doesn't support NDEF", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                Toast.makeText(this, "Error writing to NFC tag: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        loadValues()  // Load saved values when activity is created
        setContent {
            C2cTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    Column {
                        SendButton(
                            context = this@MainActivity,
                            broadcaster = broadcaster,
                            portText = portText,
                            onPortTextChange = {
                                portText = it;
                                saveValues();
                            },
                            pairCodeText = pairCodeText,
                            onPairCodeTextChange = {
                                pairCodeText = it;
                                saveValues();
                            }
                        )
                    }
                }
            }
        }
    }
    
    override fun onResume() {
        super.onResume()
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        )
        val intentFilters = arrayOf<IntentFilter>()
        val techLists = arrayOf<Array<String>>()
        nfcAdapter?.enableForegroundDispatch(this, pendingIntent, intentFilters, techLists)
    }

    override fun onPause() {
        super.onPause()
        saveValues()  // Save values when activity is paused
        nfcAdapter?.disableForegroundDispatch(this)
    }
    
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (NfcAdapter.ACTION_TAG_DISCOVERED == intent.action) {
            writeNfcTag(intent)
        } else if (NfcAdapter.ACTION_NDEF_DISCOVERED == intent.action) {
            when (val result = parseNdefData(intent)) {
                is Either.Left -> {
                    Toast.makeText(this, result.value, Toast.LENGTH_SHORT).show()
                }
                is Either.Right -> {
                    val (port, pairCode) = result.value
                    portText = port.toString()
                    pairCodeText = pairCode
                    saveValues()
                    //broadcaster.sendBroadcast(aesEncrypt(port.toString(), pairCode))
                    broadcaster.sendBroadcastWithCallback(
                        aesEncrypt(port.toString(), pairCode),
                        { encryptedResponse ->
                            try {
                                val response = aesDecrpytion(encryptedResponse, pairCode)
                                if(response.decodeToString() == "OK") {
                                    moveTaskToBack(true)
                                } else {
                                    Toast.makeText(this, "Failed to launch scrcpy", Toast.LENGTH_LONG).show()
                                }
                            } catch (e: Exception) {
                                Toast.makeText(this, "Failed to decrypt response", Toast.LENGTH_LONG).show()
                            }
                        },
                        {
                            Toast.makeText(this, it, Toast.LENGTH_LONG).show()
                        }
                    )
                }
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
    }

    fun aesEncrypt(data: String, pwd: String): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(pwd.toByteArray())
        val key = SecretKeySpec(bytes.copyOf(16), "AES")

        // Generate a random IV
        val ivSize = 16
        val iv = ByteArray(ivSize)
        SecureRandom().nextBytes(iv)
        val ivParameterSpec = IvParameterSpec(iv)

        // Initialize the cipher with the IV
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec)

        // Encrypt the data
        val encryptedBytes = cipher.doFinal(data.toByteArray())

        // Combine the IV and the encrypted data
        return iv + encryptedBytes
    }

    fun aesDecrpytion(data: ByteArray, pwd: String): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(pwd.toByteArray())
        val key = SecretKeySpec(bytes.copyOf(16), "AES")

        // Extract the IV from the data
        val ivSize = 16
        val iv = data.copyOfRange(0, ivSize)
        val ivParameterSpec = IvParameterSpec(iv)

        // Initialize the cipher with the IV
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec)

        // Decrypt the data
        val encryptedBytes = data.copyOfRange(ivSize, data.size)
        return cipher.doFinal(encryptedBytes)
    }

    fun parseNdefData(intent: Intent): Either<String,Pair<Short,String>> {
        val rawMsgs = intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES,
            //   NdefMessage::class.java
        )?.map { it as NdefMessage }
        if(rawMsgs!=null) {
            val msg = rawMsgs[0];
            for (record in msg.records) {
                if (record.tnf == NdefRecord.TNF_WELL_KNOWN && record.type.contentEquals(NdefRecord.RTD_TEXT)) {
                    val payload = record.payload
                    val languageCodeLength = payload[0] and 0x3F
                    val text = String(payload, languageCodeLength + 1, payload.size - languageCodeLength - 1, Charsets.UTF_8)
                    val splitted = text.split("|")
                    if(splitted.size>=2) {
                        return try {
                            val port = splitted[0].toShort()
                            val pairCode = splitted.subList(1,splitted.size).joinToString(separator = "|") {
                                it
                            }
                            Either.Right(Pair(port, pairCode))
                        } catch (e: NumberFormatException) {
                            Either.Left("Invalid data format: $text")
                        }
                    }
                    Log.d("YJ", "Text Record: $text")
                } else {
                    Log.d("YJ", "Non-Text Record: ${record.toString()}")
                }
            }
        }
        return Either.Left("Cannot read data from this tag")
    }

    @Composable
    fun SendButton(
        context: Context,
        broadcaster: UdpBroadcaster,
        portText: String,
        onPortTextChange: (String) -> Unit,
        pairCodeText: String,
        onPairCodeTextChange: (String) -> Unit
    ) {
        Column(modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp)) {
            TextField(
                value = portText,
                onValueChange = { 
                    onPortTextChange(it)
                },
                label = { Text("Port") },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 8.dp)
            )
            
            TextField(
                value = pairCodeText,
                onValueChange = { 
                    onPairCodeTextChange(it)
                },
                label = { Text("Pair Code") },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 8.dp)
            )
            
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Button(onClick = {
                    try {
                        val port = portText.toShort()
                        broadcaster.sendBroadcastWithCallback(
                            aesEncrypt(port.toString(), pairCodeText),
                            { encryptedResponse ->
                                try {
                                    val response = aesDecrpytion(encryptedResponse, pairCodeText)
                                    if(response.decodeToString() == "OK") {
                                        (context as Activity).moveTaskToBack(true)
                                    }
                                    Toast.makeText(context, response.decodeToString(), Toast.LENGTH_SHORT).show()
                                } catch (e: Exception) {
                                    Toast.makeText(context, "Failed to decrypt response", Toast.LENGTH_LONG).show()
                                }
                            },
                            {
                                Toast.makeText(context, it, Toast.LENGTH_LONG).show()
                            }
                        )
                    } catch (e: NumberFormatException) {
                        Toast.makeText(context, "Invalid port number", Toast.LENGTH_SHORT).show()
                    }
                }) {
                    Text(text = "Send Broadcast")
                }
                
                Button(onClick = {
                    val nfcAdapter = NfcAdapter.getDefaultAdapter(context)
                    if (nfcAdapter?.isEnabled == true) {
                        Toast.makeText(context, "Touch NFC tag to write", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(context, "NFC is not available or disabled", Toast.LENGTH_SHORT).show()
                    }
                }) {
                    Text(text = "Write to NFC")
                }
            }
        }
    }

    class UdpBroadcaster(private val context: Context) {
        companion object {
            private const val PORT = 8888
            private const val BROADCAST_IP = "255.255.255.255"
            private const val TIMEOUT = 5000 // 5秒超时
        }

        // 发送广播
        fun sendBroadcast(message: ByteArray) {
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    DatagramSocket().use { socket ->
                        socket.broadcast = true
                        socket.soTimeout = TIMEOUT

                        val sendData = message
                        val broadcastAddr = InetAddress.getByName(BROADCAST_IP)
                        val sendPacket = DatagramPacket(
                            sendData,
                            sendData.size,
                            broadcastAddr,
                            PORT
                        )

                        socket.send(sendPacket)
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }
        }


        // 带回调的发送方法
        fun sendBroadcastWithCallback(
            message: ByteArray,
            onSuccess: (ByteArray) -> Unit,
            onError: (String) -> Unit
        ) {
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    DatagramSocket().use { socket ->
                        socket.broadcast = true
                        socket.soTimeout = TIMEOUT

                        val broadcastAddr = InetAddress.getByName(BROADCAST_IP)
                        val sendPacket = DatagramPacket(
                            message,
                            message.size,
                            broadcastAddr,
                            PORT
                        )

                        socket.send(sendPacket)

                        // 准备接收数据
                        val receiveData = ByteArray(1024)
                        val receivePacket = DatagramPacket(receiveData, receiveData.size)
                        
                        try {
                            // 等待接收响应，如果超过soTimeout时间会抛出SocketTimeoutException
                            socket.receive(receivePacket)
                            
                            // 收到响应，调用成功回调
                            withContext(Dispatchers.Main) {
                                onSuccess(receivePacket.data.copyOfRange(0, receivePacket.length))
                            }
                        } catch (e: SocketTimeoutException) {
                            withContext(Dispatchers.Main) {
                                onError("No response, is server running?")
                            }
                        }
                    }
                } catch (e: Exception) {
                    withContext(Dispatchers.Main) {
                        onError(e.message ?: "Unknown error")
                    }
                }
            }
        }

    }

}
