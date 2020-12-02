/*

Working example of a SFTP connection, check for a file and if found opitionally remove it.
Uses private key and hostkey checking.


*/

package main

import (
	"bufio"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func main() {

	// command line flags
	flgRemoteFilePath := flag.String("remoteFilePath", "/home/gxj/", "remote path here")
	flgUsername := flag.String("username", "username", "username for SFTP conn")
	flgPrivateOpenSSHKeyFile := flag.String("keyfile", "C:\\mykey_openssh.ppk", "full path to OpenSSH private key file")
	flgSFTPHost := flag.String("sftpHost", "192.168.100.10", "SFTP hostname or IP")
	flgRemoveFile := flag.Bool("removeFile", false, "Remove file if found remotely")
	// flgPassword := flag.String("password", "password", "password for username")
	flag.Parse()

	port := "22"

	// get host public key
	// hostKey := getHostKey(flgSFTPHost)
	// hardcoded test hostkey
	// this can be got from the known_hosts file after accepting the SSH key from the server
	// do a localhost loopback connection on the server to get this if you need to
	// need to find a way to simply get the raw host key string of the server
	hostKey := convertHostKey("|1|C1RpNpcSDup7QZV19GXXVUocLbI=|qiAN2cLK55wjlpwaVltX8e8U0So= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTewfdggttssdHAyNTYAAABBBKE9g+mUDgnjRLNNk2zc22qLvxcc5wCjXzeZaCOB9Kt+Z3s10PTWo/a2MAaKfOPui/JxYX+PatAC4YjQD87Wxuo=")

	// if using Puttygen to gen the pub/priv key pair, make sure to save as OpenSSH format ( NOT new OpenSSh )
	pemBytes, err := ioutil.ReadFile(*flgPrivateOpenSSHKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		log.Fatalf("parse key failed:%v", err)
	}

	// split the file and path of the file to be checked
	rmtPath, rmtFilename := sftp.Split(*flgRemoteFilePath)

	// attach using a private key and a valid hostkey string
	// also included the insecure connection that will ignore the presented the host key
	config := &ssh.ClientConfig{
		User: *flgUsername,
		// Auth: []ssh.AuthMethod{ ssh.Password(*flgPassword),
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		// HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		HostKeyCallback: ssh.FixedHostKey(hostKey),
	}

	// connect
	conn, err := ssh.Dial("tcp", *flgSFTPHost+":"+port, config)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// once the ssh hooked up, attach an SFTP connection request
	client, err := sftp.NewClient(conn)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// ====================================================================
	// optional code to copy up a local file to the remote
	// ====================================================================
	// // create destination file
	// dstFile, err := client.Create(*flgRemotePath + *flgFileName)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer dstFile.Close()

	// // create source file
	// srcFile, err := os.Open(*flgFileName)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// // copy source file to destination file
	// bytes, err := io.Copy(dstFile, srcFile)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// log.Printf("[%s] %d bytes copied\n", *flgFileName, bytes)
	// ====================================================================

	// get the list of remote files and search the one we want
	procExitStatus := 0
	fileFound := false
	dirList, _ := client.ReadDir(rmtPath)
	for oi := range dirList {
		if dirList[oi].Name() == rmtFilename {
			fileFound = true
			log.Println("FOUND:" + *flgRemoteFilePath)
			if *flgRemoveFile {
				err := client.Remove(rmtPath + dirList[oi].Name())
				if err != nil {
					log.Println("DELETE FAILED")
					procExitStatus = 1
				} else {
					log.Printf("DELETED:%s", dirList[oi].Name())
				}
			}
		}
	}

	if !fileFound {
		log.Println("NOTFOUND:" + *flgRemoteFilePath)
		procExitStatus = 1
	}

	os.Exit(procExitStatus)

}

// simple
func convertHostKey(hostKeyString string) ssh.PublicKey {

	// convert the hostkey string from known_hosts into byte slice
	hostKeyStr := []byte(hostKeyString)

	// now extract the hostkey
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey(hostKeyStr)
	if err != nil {
		log.Fatalf("error : host key string is not valid")
	}

	return hostKey
}

func getHostKey(host string) ssh.PublicKey {
	// parse OpenSSH known_hosts file
	// ssh or use ssh-keyscan to get initial key
	file, err := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var hostKey ssh.PublicKey
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) != 3 {
			continue
		}
		if strings.Contains(fields[0], host) {
			var err error
			hostKey, _, _, _, err = ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				log.Fatalf("error parsing %q: %v", fields[2], err)
			}
			break
		}
	}

	if hostKey == nil {
		log.Fatalf("no hostkey found for %s", host)
	}

	return hostKey
}
