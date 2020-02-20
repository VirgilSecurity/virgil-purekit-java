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
  `expiration_date` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
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
INSERT INTO `virgil_grant_keys` VALUES (2,'845e3ad4-09c9-41e0-aad4-61161b5e2a65','gš\Z‚e3;\râr¬g‹$I›Æx[W3yWò295Ë¸ÓšÙSüÓõ5xû=‡ÃO\rqì0X{$f','2020-02-17 16:40:39','´$845e3ad4-09c9-41e0-aad4-61161b5e2a65\Z@gš\Z‚e3;\râr¬g‹$I›Æx[W3yWò295Ë¸ÓšÙSüÓõ5xû=‡ÃO\rqì0X{$f\"<ß³‡´E€O´æ§÷c—_üò\\»\"ß3ïÖCóùÉ2‘•f=àXæNæçC˜,m¬sÒÉ_»¶´	ù(÷çªò0‡„«ò\ZS0Q0\r	`†He\0@·¹Ù#ÂbLbt\"ûãŒ\\ZŠ¢	–hS5xwäù¶¾ã×Ÿ‰¸´ô‹n‡„LÏ¦¢ì\'Â:İö\\á *A$Á‘Ë’-‡\'Ôú\'¯÷w\"ßQ§³âÓÜ€ÇEH½s©Y?#A†*mX=P;je~ıÓ†®xİ×Ä!¹íäb”µ');
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
INSERT INTO `virgil_role_assignments` VALUES ('0955dde9-6c18-47c4-b37c-21f2a98a14d7','b8f477a8-634e-4da4-bb52-b7b28acf0274','ˆ$0955dde9-6c18-47c4-b37c-21f2a98a14d7\Z$b8f477a8-634e-4da4-bb52-b7b28acf0274\"ğ=“‰IÜ*­0‚ˆ0‚?	*†H†÷\r ‚00‚,1ş0û \nÍ‡Æ¤&Õ0+epâ0ß\00*0+ep!\0_;Â¯Åß€IX§h\r§–GÜtTÙf~ğú©ÆM¦\00(Œq0\r	`†He\00A0\r	`†He\00D7ç\nÌLyåXFI£ŸÎæÊûEÍl˜dM¯ü\0/ú|¼Î:ú?±ßûó38Geô0Q0	`†He*ZäÇÓxd^¦gUM“ß0a§˜˜Sh››N C\n\0p”€ğLá0!âU3¯½*Iífâyï	¦×Z1wşS:0&	*†H†÷\r0	`†He.eh–åÑÜã€¸§˜A¡0\r*†H†÷\r	¢0\0\0  0\00\r	`†He\0£0\n+ƒ¬V—Mÿ§ùàAõù†l¥ˆÚyß~ğXİTw‹ÁğDµ=ãÜ+ÄÖ—AHäÁêÎğ®‰Ç! 	ºø&y}Î/³àJâŠZüˆIØ\rQ-‘²°Â`_÷Ç‚úfù,„ßO¤ûQ—!İ\Z´ŒzÄiŠèà÷ø/~ähx¶8$®Eˆ³uÆip´¾É†S8ÎÓyÌ¯Ìçó	ımË°]ú²Óµh±jß!6£@õaèîqWéD‰ÎL³ï5±Ør\\ÇèÀÑi}›eø‰¸@O©%yÜ­0°£¼‰päCùŞÍûfK~Ü«•QÆÅ1,àˆÜÒs£`le¡9¸×öµ^}È³1°öL˜ÍBİñ‡ÆşnÙœ^St=ĞD\ZS0Q0\r	`†He\0@\'ÊwåSÜ›(¡ü]I÷´j~TÃcŞ±\'>RO áu†b­æi}ÛFZÑ,2\'ìÄ•ÎT\"òqğ^Mdı­G');
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
INSERT INTO `virgil_roles` VALUES ('0955dde9-6c18-47c4-b37c-21f2a98a14d7','V$0955dde9-6c18-47c4-b37c-21f2a98a14d7\Z,0*0+ep!\0P\rÈq›J£n¿I&†ƒœJDßÓ1u>£`¦—Çƒm\ZS0Q0\r	`†He\0@Êêœııİæû¤×L«JV%H@=\rA«³í±Ztã°(»Ğë¥4–oŠ1gÜr4ÃÀY¢ÈãQµšÕ');
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
INSERT INTO `virgil_users` VALUES ('845e3ad4-09c9-41e0-aad4-61161b5e2a65',2,'®\r$845e3ad4-09c9-41e0-aad4-61161b5e2a65\Z l\\âØ3Pş\rÏ	­—}Mp†ŒÒ/ßÅîÊQÛ„5È\" Å­_õ èT°bĞ„;^¡Ìl°O7±HFŞ6úm~*,0*0+ep!\0BW¡Y¯ĞÓ²2NWÌu§5‹+A¸¿;%ïƒn2`9&5éå<¤é±Ğ)WÈÉúÅ@¬÷äc–rø€3ZeqÕäÕ#I.•ô=PÖÑaŒl×Äğ08±lïüS*†Œ‡Øˆ^	´´_uUvæOö•œm¥Ù\nD!KáZT›EÃ:­0‚ˆ0‚?	*†H†÷\r ‚00‚,1ş0û \nšÑVM‹YÃ0+epâ0ß\00*0+ep!\0«ËY×îo²ÑÜ¹.Îà¾üñóe:Şå©PHÑAØ5Ù0(Œq0\r	`†He\00A0\r	`†He\000Aí¥v\0a„zP2vH³ıÄ®iÄÍ)²)_¸ßu~áÜ|\')œìùa3ü¡n ü0Q0	`†He*ˆÿ’ËM¶^)¦b*>&7¿0JAL{$50`Û‹‚ Üª«ÏÜàv=L¦=Àâ]€Öcâÿ7áÈ\0¡x\\\Zñ\nv$0&	*†H†÷\r0	`†He.CäÍtı¨:ÏI¡0\r*†H†÷\r	¢0\0\0  0\00\r	`†He\0£0\n+ƒ¬ç¡\nÎ,H9[PYBN·\ZrzŞUq3e€Ô°˜&¡7‚á*õW˜š#|9*ã`-¿š…»\\vÙÇ—Ñ‘¸òƒ±Õx²ê|¡ì-NqQ|ÑTèú6ã3\\À|û5Ù\"Ñ™ùæ wQN´Aã7\0}_gó²­jI¡z÷ÑzH%~€iÑõĞPÊ¯·(ÃÍ$øÎŞœÎ\ZÑİÑ	\"á0O¦L7Àq4×•+jõ¹z+y6©xİŸÏ‰¾}ÔÍP¢*‹(™8«c#¬böYÚcoÍ®ê¸y°ç­[B¾A?1ş1bagõyEZF:O $pN¯SÈHçî…ºFÍïW«øä;gÑ/GŸÎÕ\ZŞbÌn´S±‘B­0‚ˆ0‚?	*†H†÷\r ‚00‚,1ş0û \nšÑVM‹YÃ0+epâ0ß\00*0+ep!\0\"¾grH²|gš€”k1i–x²¢Mg ú!+Î¢—Q[0(Œq0\r	`†He\00A0\r	`†He\00Ø­ÿßãa@®`!Ä8Ø73°2±ç^ìp³ûPi€mx©Ú qZlkVİm\ZñB^0Q0	`†He*XûÀ+»±\"tÛ…’¯xÁ0èEš¿g2´¾;MPcK{3âZ¾¨IÊ\Z7‡í«2SMU™ÿÙÛÖ~VL300&	*†H†÷\r0	`†He.Èmÿ©¾;×¹PÎ¦¡0\r*†H†÷\r	¢0\0\0  0\00\r	`†He\0£0\n+ƒ¬„{’m?èRg\Z0»hÓ%\rL[×Kpv&Ï9!SmvS×Ğ‘fqòÇû!‘ĞâZø¸+(,”Qiî[\0ìZ÷.ø’‘ÔAÎŸâQª×áĞ\Z9¼d‹PŞpÛ‡1Ê\ZDÎŸaÎĞ¸ı¤¬¯]	õ“h†¾Š[Òs4ğY»K:ØŸïÚÚÿevØ}6i8ë8qP0íŞGú»ÄR$bó£Öëî^Ÿ…˜Æû°`!¸:¾»!¡VåL-úÅ%\0;[+•uöpl*³_¦Ì`JS=ÓcTT¯âüœQ2^”S7ÀnÄ¸Q½d$`6¶Ği®Î0GÀÚšx]ç£@äxp·7¦feèùî©Ã]tnÌF“E±½/JP²õ½ =ğ„Û¨ÓÃ¡¢\n¨ßEø£\0µbØT×gÄ:Î£şê$V%»zQM¼\0vØ›§ßâ»d‰A©?Nvê_ï*~\'›kÀ®Ûv@á\ZS0Q0\r	`†He\0@Ï»€ºS´©–]–©—N±ÿ³-Û§‡â³uõ‰TñĞ5ä>ÃqoÅ:¡Xğ?Tÿ©cBı°eçC¡°›\"APT{{7ëœDWc©ÀŸölåÙwŒ››L°!ÓÆîÅ†wš=ug¸ï?®rÉ$ÚAWrEÇ*Üè“–Oã¬(*A`M]®U½¢¿\"25Pâó ò8¡!@l9OD¾p:×1±ÿˆr|jnğ_?˜ÛOÍvÕd64Ÿí/áVÇW0:A©8­¬zJz+DY)ÁŒßô9>PiÑÚ#ùNôâÛ]ÀIÉ¬Ë#®ka>Â…)bDEm¾I\nÒ;!Ÿ‹Ï†B'),('b8f477a8-634e-4da4-bb52-b7b28acf0274',2,'®\r$b8f477a8-634e-4da4-bb52-b7b28acf0274\Z ø§Ğı×{%İ\rÏ„®¾¼ˆÈEé÷¼¯K_Â(ï­ÕUo]\" ìa‰şÁµÕnW§¬Ë|Xïâ›„ƒi<õÀÚ}d$Î¤â*,0*0+ep!\0 ‰¢Zúm\0–Ó=Ÿ÷G9¹ÖG§*›ı¤„>{8ğæè2`»t|ï›šñ¹µ«\"ix@pöFöÁ#&fÌ+y ;Éƒ8œèñåíÒ«v#º 2\\¯™\"ŸÒ#kG«ôL\\–oíœÊJÊmå ²y‘êh,C!æŒµzNŒè\"chã6¯:­0‚ˆ0‚?	*†H†÷\r ‚00‚,1ş0û \nšÑVM‹YÃ0+epâ0ß\00*0+ep!\0&Íèi\nËyãÁ˜Õ–!L×Ò·=)o\"<-<2©M´0(Œq0\r	`†He\00A0\r	`†He\00ğd|Ú¶?±*&H$­?DÿöO=’‡şÌZgnˆ(Xò¡!nÁtàÏ_\\÷¡´¯DÃÚ0Q0	`†He*âüHú­’Vlñ¨S^ÚŒ0Ô¶nZ™û\\P ª*ª§P—O:ğ\"·‹@5-\\º°ær\r•îÚ@ÎœJ` Ö#¶0&	*†H†÷\r0	`†He.eÂ]ÿzÁ1ĞúêŞ$¡0\r*†H†÷\r	¢0\0\0  0\00\r	`†He\0£0\n+ƒ¬-(äYÜzoç]+œQøLcñG<ŠlÄR;\nI¯¤EŞÍ„‹@ÉÒRN&Q6’Ù‰¬\"Ç4¼Â,À~\nÜ\'ä	µ“Nbø\'Œ€Ñ‰ÚÍ(Ï~ÍMë>q×ÓâiTòH^ºŞ­=â©z ì0+étàmµKKƒË8‚+\'S«Jvà‰xQ§nì£™y¹•‡/rÑõPâÚóÙ\"A«V+¿•Ş £4´eâúæ¶nŒ*`o¤M~–ä†4ÜÈÖP_xñxQæÍ¥ÙŠU˜m¶´àk¶\".4ÎhÄZ¯øŞmQ·i“Û0ä@;¼•Ù\r—L½–ñŒHÁ!w3ûI¦S?á¥k_ƒ(Ï×·uÉ&q¿»²ÃÏB­0‚ˆ0‚?	*†H†÷\r ‚00‚,1ş0û \nšÑVM‹YÃ0+epâ0ß\00*0+ep!\0ŞÎ?  |-ÁÂä?Š›cS\rº[V¬6/x\0¯÷\0R0(Œq0\r	`†He\00A0\r	`†He\00ßzÈSÕtB2³f33‰nŸX alà_‘Aº¹ìĞ¤%Úsı†r–˜lP˜n0Q0	`†He*§6vLı“¿­6‘ŒZœğ0î‰À­(±³ç¼ÂğQšªh”R¡$Æ†;l\\ZÌ­%§°iñ¼€ù\ZªF\\0&	*†H†÷\r0	`†He.ĞE÷€«V\nO¡0\r*†H†÷\r	¢0\0\0  0\00\r	`†He\0£0\n+ƒ¬šÌërëŞÿsu)4à.j1yÉÙWÆ,\nòÁ-ÿ ¤E­x±ùşd˜\'•›Dñµ¯ §ŸoJåô¡áX|ß¶ËÇFš`¾Ö‚Ú	E«ÒˆH‚\";)]‚ş\0ş«Ç˜c÷=e<‰|LÆÄÛ=t±=t:õÏT#.éªÚú¨øaA_àª;Q¹’Òç½B\"\"­o¯CZ9N³‹\\Xêÿ®@\\yãTú¡âgC…¸Eë  ÒÃÍïş¨% V&FúYÇÕ^EÈµ²é7š”Uˆ5?ÂN²boé“ÁÄ|úâfÖaFÃÎÙ5H(´™L4—ƒ~¥”?)¹øùî)\nÇ°Ø><ø£¢ÍtÅ.œ*DkŠ@ÿBË5añ§—€ÓJPÍ^TÆÆº›¨$.Ú*Ì¾ß+…½+üÜÿS’ì#_î²ˆïÅ±I¹/	|a×¾O~$ğÅb÷(®(ŸSØ¿¨ÅRix}9hsŒÚ¶Jæ\ZS0Q0\r	`†He\0@d}«Œˆé§Ç/E9zî}>³³ê4i\r÷¥˜ã.a¿JõVƒ…HZ³IuH7m„@«Sñ9‰-g k2Ş\"A}‚8K&*¹Ò¨x†µµ#†i{ôÙ¸–±¬×ÚÜ†KóÖŞ»W•…Œ|¥ÔøyâfÄhÉ]­od	¢4U*W*AïkB0ÿ™™JØÎ­ÍØû*t]–Y‡‰ûRz‹Åü5kq*ZS²³ìÓ3½á3Mì%ş)ÂÑcRlS#‡±é0:A~Ê<;\ni¢:)´oµ¡5\"±Ûv29«[¥æ›&Á\r½£t‰\'*èÃğí\"í1±a½{èû¸e‹…/');
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

-- Dump completed on 2020-02-17 15:43:32
