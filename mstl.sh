#!/bin/bash
# prequisite: 
# sudo apt install cabextract
echo "(i) Downloading MS CTL"
curl http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab -o authrootstl.cab
echo "Extracting STL from CAB"
cabextract authrootstl.cab
echo "(i) Converting STL to ASN1 indented short dump"
#need to add date to asn1 file
openssl asn1parse -i -oid msoids.txt -in authroot.stl -inform DER | sed 's/.*prim: //; s/.*cons: //' > asn1short.txt
echo "(i) Writing out full asn1 list"
openssl asn1parse -i -oid msoids.txt -in authroot.stl -inform DER | sed 's/.*:         OCTET STRING      \[HEX DUMP\]:/Thumbprint: /'  > asn1full.txt
echo "(i) Extracting thumprints from short ASN1list (based on asn1short file)"
cat asn1short.txt | grep "OCTET STRING" | sed 's/^        OCTET STRING      \[HEX DUMP\]:/Thumbprint:/' | grep Thumbprint | sed 's/Thumbprint://' > thumbprints.txt

#need to add date to thumprint file

echo "(i) Downloading certs"
input="thumbprints.txt"
while IFS= read -r line
do
    echo "(i) Downloading $line"
#    curl http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/$line.crt -o ./certs/$line.crt 
done < "$input"

#ez vszinu nem kell
echo "(i) Deleting old subjects lists"
rm results.txt
# idaig

echo "(i) Generating final results"

input="asn1full.txt"
while IFS= read -r line
do
   if [[ $line = *"Thumbprint"* ]]; then

        certfile=`echo $line | sed 's/Thumbprint: //;'`
	certfile+='.crt'
        subject=`openssl x509 -subject -noout -in ./certs/$certfile -inform DER -nameopt utf8 | sed 's/subject=/Subject: /'`
        echo "----" >> results.txt
	echo "----"
	echo "Subject: $subject"
	echo $line
	echo $subject >> results.txt
	echo $line >> results.txt
   elif [[ $line = *"MS CTL allowed EKUs"* ]]; then
	read line 
	read line 
	stroffset=`echo $line | sed 's/:.*//'`
	openssl asn1parse -in authroot.stl -inform DER -strparse $stroffset > tmp.eku 

	grep OBJECT tmp.eku | sed 's/.*OBJECT            :/KeyUsage: /' > clean.tmp.eku
        cat clean.tmp.eku
	cat clean.tmp.eku >> results.txt
    fi



done < "$input"


