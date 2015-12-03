rule scada_dnp3_controls_in_malware

{

	meta:

		author = "Dewan (@dewan202)"

		maltype = "scada"

		filetype = "pe"

		yaraexchange = "No distribution without author's consent"

		date = "2012-10"

		comment = "Detects DNP3 functionality designed for industrial controlled system"

	strings:

		$a = "DNPCommandMaster" 

		$b = "slave.???"

		$c = "SlaveResponseTypes"

		$d = "MasterStates.???"

		$e = "TestLinkStatus with invalid FCB" wide

		$f = "Confirmed data ?? wrong FCB" wide

		$g = "FC_PRI_RESET_LINK_STATES" nocase

		$h = "FC_PRI_TEST_LINK_STATES" nocase

		$i = "FC_PRI_CONFIRMED_USER_DATA" nocase

		$j = "FC_PRI_UNCONFIRMED_USER_DATA" nocase

		$k = "FC_PRI_REQUEST_LINK_STATUS" nocase

		$l = "Device restart detected" nocase

	condition:

		($a or $b or $c or $d or $e or $f or $l) and ($g or $h or $i or $j or $k)

}