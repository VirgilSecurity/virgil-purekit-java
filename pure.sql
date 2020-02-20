CREATE DATABASE puretest;
USE puretest;

-- MariaDB dump 10.17  Distrib 10.4.11-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: puretest
-- ------------------------------------------------------
-- Server version	10.4.11-MariaDB-1:10.4.11+maria~bionic

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `virgil_grant_keys`
--

DROP TABLE IF EXISTS `virgil_grant_keys`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `virgil_grant_keys` (
  `record_version` int(11) NOT NULL,
  `user_id` char(36) NOT NULL,
  `key_id` binary(64) NOT NULL,
  `expiration_date` bigint(20) NOT NULL,
  `protobuf` varbinary(512) NOT NULL,
  PRIMARY KEY (`user_id`,`key_id`),
  KEY `record_version_index` (`record_version`),
  KEY `expiration_date_index` (`expiration_date`),
  CONSTRAINT `virgil_grant_keys_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `virgil_users` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `virgil_grant_keys`
--

LOCK TABLES `virgil_grant_keys` WRITE;
/*!40000 ALTER TABLE `virgil_grant_keys` DISABLE KEYS */;
INSERT INTO `virgil_grant_keys` VALUES (2,'cd509ac0-9a38-4eba-ab77-abf50023247e','÷J-İíZgFZò®À4·µk¾%²[=x2Fâ¦id0Ä_<‹‹%¢Ç.$p²³Íâ-ÂUÄ‘x«óÁ”',4735795471,'´$cd509ac0-9a38-4eba-ab77-abf50023247e\Z@÷J-İíZgFZò®À4·µk¾%²[=x2Fâ¦id0Ä_<‹‹%¢Ç.$p²³Íâ-ÂUÄ‘x«óÁ”\"<që±ıè‘ù³ù±rµÒÔ\'Ò†¬år@o3×Ü£ñ,\\w²’óÙµcÌL—şh¦íH&’Œ[éë(Æ¹ò0‚šÒ\ZS0Q0\r	`†He\0@k}®eFµ¨Æ²wËáfi	©èX©Ó¾¬Rù¡®vÍÓ6÷!£ÁÊûTÑëSPçL§×`‚¥‰<E‚„NøÑ *A`ØÍï8âøèù¹H|ÊàıM\rdgÊYJÑù.û$±q–ĞJÉâ÷”Â.ù¥Ÿ\"ß {öï$ë>ÏKœ$·');
/*!40000 ALTER TABLE `virgil_grant_keys` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `virgil_keys`
--

DROP TABLE IF EXISTS `virgil_keys`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `virgil_keys` (
  `user_id` char(36) NOT NULL,
  `data_id` varchar(128) NOT NULL,
  `protobuf` varbinary(32768) NOT NULL,
  PRIMARY KEY (`user_id`,`data_id`),
  CONSTRAINT `virgil_keys_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `virgil_users` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `virgil_keys`
--

LOCK TABLES `virgil_keys` WRITE;
/*!40000 ALTER TABLE `virgil_keys` DISABLE KEYS */;
INSERT INTO `virgil_keys` VALUES ('cd509ac0-9a38-4eba-ab77-abf50023247e','43069438-826a-4b93-85ac-bab0bf75c368','­$cd509ac0-9a38-4eba-ab77-abf50023247e\Z$43069438-826a-4b93-85ac-bab0bf75c368\",0*0+ep!\0IGécgÏU|y \ZE<¬Vnß%3³s™œu0+²5í*ú0‚v0‚>	*†H†÷\r ‚/0‚+1‚ü0û \nú+ÛÃˆà-0+epâ0ß\00*0+ep!\0ÚVü3µ§ÅÀ/Aöò!âùCLŒ+˜\0–/äÊ”–\Z50(Œq0\r	`†He\00A0\r	`†He\00=1ñK`lx¸ùKï3şÁ!:àò³æTçf³ÍÏn«­ô°¼U\rŠŸ§3ù0Q0	`†He*q¹VZ^èï›ìÄº(Ë9…0Í­’0cŞ¸*•2&\0|\'K_MljØv¢´e³t)Ñ>#amû_%Ò»«/$L0û \n·äPÊ>Å0+epâ0ß\00*0+ep!\0/×\'Ñyô“%ãŒ¹ÒW5Ôƒ!ufsÿ§«Ú¹> )0(Œq0\r	`†He\00A0\r	`†He\00…u³¸ª‰©iŠS•š\'öÀ{%Fu\'†wQ}>4­èkYÙß V n­OŠw7>0Q0	`†He*±ã%ê±¸8K²D$†Ê70ñ$ÕlG~ŸË9mMB›¬ÀŞ‚ª\0L—\'›NÓøGšİ»¼£ï\\FPXÀGÒı*r[OÔ0&	*†H†÷\r0	`†He.o\"`Ï~`CT›Kƒ¡0\r*†H†÷\r	¢0\00 0\00\r	`†He\02±ÁŠºÎš¬.[\Z\0\0O®K«×1\\Seî:oÄ-6Ü¬ ˜es;Û8ÂfƒhôŞ,Ærã‚ÿºòD-›l=s‰Ö¹“†7€cF!ú¸ŒÊâ\Z‹şÀ{\\9%)ÕšSviùËÕú0@±Ü\"°tÏĞĞ.~œ\'º—éü~çĞ~ÆšŞe5o$ØI’Şòïüg÷ƒ/U!{c£ïÚõ,«°Ù~±æ´)ßç~˜“Ñ™k˜¥»ygU\ZS0Q0\r	`†He\0@t>¯@[äÿk¤H±t%öºœÁ7¶\\<eĞS‰¢FRÁ9*CØ\rót)\"¡yåäéA¥œs\0|²M\"cºË'),('cd509ac0-9a38-4eba-ab77-abf50023247e','df387224-419e-4e64-944d-1485694ecb8c','­$cd509ac0-9a38-4eba-ab77-abf50023247e\Z$df387224-419e-4e64-944d-1485694ecb8c\",0*0+ep!\0ÛÜˆ‚àc‹_3?FPî³eZÂÔ+cx=­:©Aß*ú0‚v0‚>	*†H†÷\r ‚/0‚+1‚ü0û \n·äPÊ>Å0+epâ0ß\00*0+ep!\05\\ó•îHnŠÇ}\ZšËZ4uUs#èØLz¢àb»î5s0(Œq0\r	`†He\00A0\r	`†He\00”íó~Pô“1pS™ÊCÒ©Ù&Ñ.XüíUkeJÛ­t*“¸, \Z™ü>İR0Q0	`†He*ÃL¥ì=±§Hğ0¹Ïœ0lÓŒŸ¦[‡ñ#Ÿx¿±ëdİYM™±àõ*¬ø÷è]ş†Qg+áÀñhÈß\Z6{F×0û \n^Y6Í»U~0+epâ0ß\00*0+ep!\0:±B×gÏ€57ëEO/VÖÓ=~îGLƒ‹BX(yó0(Œq0\r	`†He\00A0\r	`†He\00ÕW!BÕ]Ùm$¿³J×‘NÏØÈ°{cEïÔ®C:»¯P\\wä|ôHReÈ70Q0	`†He*è\"Å@êÙ‡â	.ÃòÈ¾F®0ß¾²:y &WêHíQ2­¿‰tŠİ9ìóÁ	›2£ÍÙz|S°¨å÷Ó¼Ğ0&	*†H†÷\r0	`†He.è3§Øÿæ!iæÛ¡0\r*†H†÷\r	¢0\00 0\00\r	`†He\02± “½…n8Ÿë¨½—Á_Ó¶VwŞo…aw”jALÔ>îî	/¡[7~YÜbYÉÀäñ\0iï`sY›Ao°)¶oUÚÃTÂâtS‚w0›¾€nşH’\"Ñæ¢äü´¼9]”ÇgZ®£Og¸ÿÎ¤Î¥òÌ‰ì\n™Äa§\']ñå™ô!E·j-;CÂÛögåS}ªæ¢\n.…£V4¤ujö÷+~®Zh\ZS0Q0\r	`†He\0@;±Qjf^¾”·Ù­s7Å\n¤&å‰ŞüIqmü€$F8^}iÚ¨Oˆ{L¼âÿ-Ş÷áûêªĞáö(Òˆ§T');
/*!40000 ALTER TABLE `virgil_keys` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `virgil_role_assignments`
--

DROP TABLE IF EXISTS `virgil_role_assignments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `virgil_role_assignments` (
  `role_name` varchar(64) NOT NULL,
  `user_id` char(36) NOT NULL,
  `protobuf` varbinary(1024) NOT NULL,
  PRIMARY KEY (`role_name`,`user_id`),
  KEY `user_id_index` (`user_id`),
  CONSTRAINT `virgil_role_assignments_ibfk_1` FOREIGN KEY (`role_name`) REFERENCES `virgil_roles` (`role_name`) ON DELETE CASCADE,
  CONSTRAINT `virgil_role_assignments_ibfk_2` FOREIGN KEY (`user_id`) REFERENCES `virgil_users` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `virgil_role_assignments`
--

LOCK TABLES `virgil_role_assignments` WRITE;
/*!40000 ALTER TABLE `virgil_role_assignments` DISABLE KEYS */;
INSERT INTO `virgil_role_assignments` VALUES ('6ff0177a-f155-4f65-a120-02a550a56fed','5b61ad08-ee4f-4644-b43e-fba28c75b4eb','ˆ$6ff0177a-f155-4f65-a120-02a550a56fed\Z$5b61ad08-ee4f-4644-b43e-fba28c75b4eb\"^Y6Í»U~*­0‚ˆ0‚?	*†H†÷\r ‚00‚,1ş0û \nú+ÛÃˆà-0+epâ0ß\00*0+ep!\0è„„ø˜8]jrÂÕìĞ€’š¸Ğ<Rá©­gË[µù0(Œq0\r	`†He\00A0\r	`†He\008,·/³—¤¿~Wi£çí-é¬rwgí¹fkfyEÔ%ò\Z=š”ø:Ö\nı†ø0Q0	`†He*gI·Åë˜»y!qßf\ng0G¼¨<¸I-Ç	&ÉA9\"«´5DGœIø¡b9™)Àê6˜O!„r‚‹Z†\0¤\\0&	*†H†÷\r0	`†He.ô¿ÒòŒøâ*|¡0\r*†H†÷\r	¢0\0\0  0\00\r	`†He\0£0\n+ƒ¬\nİ:Öù£¾899¬D©%ë;T^ˆ¨ÎÈo¯ûˆòôÁhT{ ¶Q\"çö/oÔ»şí^ã‚Ì.ø\"«sÙ^ÏË™B&.àˆØ]6kŸÁòJL$‚Œ?ÉŒë3Ÿ•LfVj(®ì¸ºÒ§{óÖ@vû€Ç¸#¯Ö8wìsF¯PëÃ‰[gS-¨¹özg>;ÿ(H«{L#„©Äw²\' ‡ìHPÏ#¨Àğ°w×¿^§yXÛè›è{ˆwà |\\ª°IPGyk€ÚCEø:lR\Zƒ´zlDC×¢Ù”W¥½´>—ÕS1OwíS¬0¾:\\¯Ÿ—TŞHíôp®ıIîÍÕ¨¬áĞÏ$¨ª9,Ş©IÈ§¨İ]ñÆëÅ\ZS0Q0\r	`†He\0@ì~­|æ—ŞUÉ˜}kuÅhb´ı5ÊÁ¥#›XáM¤ÓàFF	£4b†o8ğepÙö)û¬!{W²`@vf€z');
/*!40000 ALTER TABLE `virgil_role_assignments` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `virgil_roles`
--

DROP TABLE IF EXISTS `virgil_roles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `virgil_roles` (
  `role_name` varchar(64) NOT NULL,
  `protobuf` varbinary(256) NOT NULL,
  PRIMARY KEY (`role_name`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `virgil_roles`
--

LOCK TABLES `virgil_roles` WRITE;
/*!40000 ALTER TABLE `virgil_roles` DISABLE KEYS */;
INSERT INTO `virgil_roles` VALUES ('6ff0177a-f155-4f65-a120-02a550a56fed','V$6ff0177a-f155-4f65-a120-02a550a56fed\Z,0*0+ep!\0Ç. ì‹éZ»kä&îh›w¯óHm	›µ¹¤¬4ÉC\ZS0Q0\r	`†He\0@m9:æµÈ‘ï«ÿ8ÕL×«\0c%ÖS?x´Ô!ç[!ÓI}íİùĞÛnÃeÙy–nátäNÒ./È=pë=S');
/*!40000 ALTER TABLE `virgil_roles` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `virgil_users`
--

DROP TABLE IF EXISTS `virgil_users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `virgil_users` (
  `user_id` char(36) NOT NULL,
  `record_version` int(11) NOT NULL,
  `protobuf` varbinary(2048) NOT NULL,
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `user_id_record_version_index` (`user_id`,`record_version`),
  KEY `record_version_index` (`record_version`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `virgil_users`
--

LOCK TABLES `virgil_users` WRITE;
/*!40000 ALTER TABLE `virgil_users` DISABLE KEYS */;
INSERT INTO `virgil_users` VALUES ('5b61ad08-ee4f-4644-b43e-fba28c75b4eb',2,'®\r$5b61ad08-ee4f-4644-b43e-fba28c75b4eb\Z TV{n‹¿	Á@ïe’Ê]4zÈÂKıƒ\0ÉNt¡\" TM7å[Eã±\\¿)i[,]åãíw’§Ô¹™r\0µhÕ*,0*0+ep!\0¬¶ ½^…)åÌÎ4èÖ´ñŸLk\ZïHÿæ>1‘ŒËB¤2`8M‘¾\Z3›\'¾º\'.†G%pÑƒù£yt×\'0İğê†¶C×¸á\0Ù‘­bÃxÂ’rvåy<D‰9`çæãŞ–n‰(ÕY”G^Ós›Np¤åøï$è(eĞbÀVë	”-ª§:­0‚ˆ0‚?	*†H†÷\r ‚00‚,1ş0û \nE›¥úâQL\00+epâ0ß\00*0+ep!\0I)î>Y`‰ø¼âåéBÁ“ª<:¦~8ªS~-G²²|0(Œq0\r	`†He\00A0\r	`†He\00‘yczZ.À?ìÌK~Ñ$$şĞòŸ0t“’|”>uìp×šà„Ğ+¶{5H,”;Ä„¶0Q0	`†He*N9l(Fâa\0A—L÷ôÂ0Ö)Òè0ûÈ‰ºú´ÆÄ$_5=I–ïv1‰81¾ŒA8‹(«º¹H»˜Éöo0&	*†H†÷\r0	`†He.@¨\rÚîĞ/8¡0\r*†H†÷\r	¢0\0\0  0\00\r	`†He\0£0\n+ƒ¬ÏÈñÂŸXC„Kè÷õ¿£ö›Ø‘ï#’Ë:6ÛO¦¯ŸM‰±Òdë]¿z%rl»S®y?!²Îv3®2­‘\r½­Ûbõ/SÖ/aB´úê$û_¿òxÿK¸Ëxâ:‚¬ìjw£Ñ­šZµáéÑÊ.ÿxóBb–I¹¡Gl	‰C^î’fN#¨õ´šh«èÅß»*Tà9sT!¿Ybô³-\\»ı\rÛ¥\" ¼$¢#öû4yÀ?ú(ĞŠG\\,$Aı\n ıİ!GXz*­IFf.£‚ÌW3w¦ãgEP°`Ç\\ËpÌÔ:VnBwë«{är¶“ÇéôWŒî”Zpù°o,M·ÿäæÆŞ9İZ Ö# ü}mjŸáB­0‚ˆ0‚?	*†H†÷\r ‚00‚,1ş0û \nE›¥úâQL\00+epâ0ß\00*0+ep!\0¹\\Ù^ÖÑ+t(^‰k“íëİÉ‡<6Êè\r¶bšS¥¹0(Œq0\r	`†He\00A0\r	`†He\00‹Š™0jéÁá=Rƒ\"Phù\nĞßÓõ\rŸSáHê@u¾kùŞóÛ£+çxí¶á9&c0Q0	`†He*WÚ$Ó“<›Ï´Z?NÉÊ0›ı`:Âí?P~{º‘Æ„÷·+mòÏæId’ÀÊ½nRÃ”ñ»Ü$u‡I¯¦0&	*†H†÷\r0	`†He.xW\\Š81€Ì	;º¡0\r*†H†÷\r	¢0\0\0  0\00\r	`†He\0£0\n+ƒ¬™ìAIæç$	á¯ı6îı¦-RM%(I½¾à3•F€Ù¼ÉËœ³›jCíÑ;^vû\n6b	·d3:é¸æ=2wXNMáêîÆĞU-÷Á‘6O˜6Œı|†VåXÇ})ÁôƒNíä½ºò´Ùñ–k	b<>X‹âö’Í¿\'u_{hµC‚öâƒGÄYDO£h8©î…Än»ZQ}.xô§åõƒTèš­ºŸ#C:¿N­â™û—ûí/±Ï„†Ü„\0™! #Z›ôNWò»{”ûuq­aqÁ_®äë¥ŸÁu‰]âOau4FÅ%noöK‚\rÛüšq­lŞº¢G™a G3Şº0Ë:ıCéP·ír—6¾E’|®~JPñŸšFy`8†Æ:X7\"¤·á<œŞ0ï¤Réø6)&_œÙ\'o·ÙÉx×Ä¨±±Òwo\0ê¤\Z+ğb¹½õ“=º¤“JnV™©Q\ZS0Q0\r	`†He\0@•*“õ´ò~©—Xh4óÃ>²‘.Æ6¬	š~oé\"ˆ?m\0*VDT¦¦­‹J*ß8>Xò¿KØô¥Í«y¼\"A‚K¡ºãô<èÈB¢Z¥pš_MÅ<)zƒ<éÓÿüğè³vo7~võw°¤÷m†v‚q°QÏ†^bu*A†‡µğŠ|G1«Mæ@t{`ç]ı qÍûV¼R®×}sJİXJ$ëj†uCÏùj­•ùEî±½}¬áÎ=Ú*\rrı0:A ìÊ¿ÖÑõ\ZPª¨áéxãm!şs¼o™?Æx~4G†v-oÒ\n%üSôìÅ‘!Öê,ó‚™>€!K,Ûvê'),('cd509ac0-9a38-4eba-ab77-abf50023247e',2,'®\r$cd509ac0-9a38-4eba-ab77-abf50023247e\Z \Z»¤\Zû“g}5€$Ñ}Dxà›2©Rë—Auo)ÆZ4(J\" c%÷{AëÈzlÒ˜l^ ¯ìcX\\\'Ğo·nÆ*,0*0+ep!\0»P×¯ç¾úKptSX-R=×9\r–{yŒÊ¤˜7Æ2`;ço\"Û~A;Õ”³ßdİ>&u£]¨£•EGÆ@HToéPÃZV¡üh]{ÚÄÕKİş#i¾ŞÉ1èy\"Ø*Í7b^O?!³.Ô.°ô[åêåıkÔº»!åñ]¨øŸ\\Áp:­0‚ˆ0‚?	*†H†÷\r ‚00‚,1ş0û \nE›¥úâQL\00+epâ0ß\00*0+ep!\0{cP\n£·Œ‰÷/ŠC6¾¹–J	2˜£NÄ%XƒÈ0(Œq0\r	`†He\00A0\r	`†He\00€{æ¥$hIY1‘x\"Ó¿b}¯R<6q>ß¢Âu°y(jl$\r[ªËÓ¤ÓØj0Q0	`†He*BÛ¹Š¨)ÊÛH|ÚV_0‘—Ô´A¤×€f$ĞF²­i: L×\r‹Sì×óÆÓ™¼>·úp©íü¶¨¼’0&	*†H†÷\r0	`†He.•”ÎéAÿá)}½¡0\r*†H†÷\r	¢0\0\0  0\00\r	`†He\0£0\n+ƒ¬¨²1ÀŒYˆéˆö%Ó¤KáŠŞ7},Å-F?¥;«ò}ÖéÔ³Ÿ­á=µaTí`\'¬Ëıi=cöëGV˜™k_Ëbg›ë+#âŒ%Sñøşp†Úïã8µ+!”‘ÿ&3D¹±@·V £„Zu\rHÓA_/Ã³9ƒè!&‘z¶tç{@›·+>™éğèûáÆ;;:¼’ö4¸‰ÚøP&Cs¹Aû¡FfÙò]yš•ò r¤úfÜã–sèÀØ\r*ÖÓìdi°[aİ±éï0Q7G`Ô{WZÒCIWÂy¾Z{.X€ş†ê„ªäR»P9êøğ$°İëŞ¼p˜slì¦KŸ¹oï£¡œ‘?Êl¶¹£Ü–Ù)dZ÷¶&B­0‚ˆ0‚?	*†H†÷\r ‚00‚,1ş0û \nE›¥úâQL\00+epâ0ß\00*0+ep!\0Îµéï+\'®÷¡Û¦ğ`;ÇdTtÃ§|Ì£ÔC¼ß0(Œq0\r	`†He\00A0\r	`†He\00XÓIÁÌŞpÔŠ¦b¼|g¿¬]©Èk®*Dòè¥‹”[±CüığlPu<ù”×\0õ0Q0	`†He*`Ã Í²D ÿâj#Ü0HFWÃïÊøí™2ŠÔ#)\0dû5Ã:TTŒ]Ç±ƒÂƒù˜ÔÊ›ÛNçD§+ÏQA²‰0&	*†H†÷\r0	`†He.°\\rŸ5šG…yµuô¡0\r*†H†÷\r	¢0\0\0  0\00\r	`†He\0£0\n+ƒ¬¤ä ë$m]‡à$Ğ¿¸&1¥>{]ñ,3Gï³L|¹AdKPQ†(›¥\'3@æ¸+ÌF\rn¤R7û§ª(Ànd=ºw=®§ˆØ‹pô‰,ˆ/öFïÌ¾1šŒª×r¢ó6€M¢·ª[Ñ¦—¬÷AÌF‰,yî‘æ=Ò´ó]Lk?UC®	öÉŠÖˆx¢àÂ3!6Ä€|$)”şú5™\"Ó|–´ûgh£– ±ª?oW’ôŠ†3–h{RÃÒRãşw	XÊîéÊvYÓ­¨‚ÏXÙ¯3ÉkŸ„­‘/o2Ì£csA‘^ö2ãÇ®wò‡®0A`·uŸÌ¥MZ	ôYgŸ`ßJ»xÄŞiŒ¤|Z:6ê‘,ÔŸ‰®\r>£JPd4 ¯½Oãq•íiy$iQ­Óˆ’q†jº“I\'Jòşö5j‡ÒçŠÃîPÃû:çáh=ån¤¥x„ŠmçÚ”aıÌ’z÷è\ZS0Q0\r	`†He\0@¶À›â@ı˜¬I‡íö—Ğ©Å<|ŞÓ±2Ed/nÈC£—„ëûÄ*Å‡Š¯]Èpy¾J2#Ébw×£ãó„@‘î\"AÒa9!/ÏßO@Ê¬ú µ…ãàaxL;ÏÓV‰Ò*Ãâ$†¸1P„etó; ¶‘›NV Æõô¸Ç\\·)İ§J*A—ªnt0=è/ÎÜmS‘¿¥÷Iÿ.F v;aÿ×÷Ìá±ò:ÆmÀ¼\0ƒ3ğù|uüL`RRA)§¨™\\T0:AÁ5&Åe¢—HV„5-oÜõ\'Íîz²ğæ™$AÉm\ZÚ	#‚Ö‡îYÇ@øt)ÊJåH)Ç›‰•rã$Cq@');
/*!40000 ALTER TABLE `virgil_users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2020-02-20 10:45:34
