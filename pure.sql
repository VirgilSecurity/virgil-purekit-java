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
INSERT INTO `virgil_grant_keys` VALUES (2,'be48aa42-e792-4933-8e47-4e5f27910c09','Sßâ=i—Ÿ—Uæo‰ÖŞz±Ğ*€ÊÎ–‘å‹í;ï¦¯‡$Å‚C“@¸XaŒÉeŠœÀ`%$-tÎ4ädí|',4735795942,'´$be48aa42-e792-4933-8e47-4e5f27910c09\Z@Sßâ=i—Ÿ—Uæo‰ÖŞz±Ğ*€ÊÎ–‘å‹í;ï¦¯‡$Å‚C“@¸XaŒÉeŠœÀ`%$-tÎ4ädí|\"<µ@$z¬Mo{TwÂíU‚^oóESûÜ’Ÿ¿,qĞU½Y/{$0ôwÏE†ƒNÒjôù\nrb­Û*7J{<æV@(æÉ¹ò0æ…šÒ\ZS0Q0\r	`†He\0@ÍÿKÇá± ƒşlµXé—	mU£ ±Ÿ¯œÑÈ@ÄšUl¸c·K;]Şº7I&¹Ù1ÛÎ:Ï¥ *A¿pğ1-tcT¹lˆW¿9›!bWkª\\)gr¬w×\nÅ714Íî}ÔY˜†âV\nœÑp=ı@$N Xi©gÙÏİ’');
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
INSERT INTO `virgil_keys` VALUES ('be48aa42-e792-4933-8e47-4e5f27910c09','242562b6-98b2-44f8-b7ea-98d22798a94e','­$be48aa42-e792-4933-8e47-4e5f27910c09\Z$242562b6-98b2-44f8-b7ea-98d22798a94e\",0*0+ep!\0Aã¥‹¡íãÜMi÷mÅ•Ş¼Ív#z8Ó§ï´|*ú0‚v0‚>	*†H†÷\r ‚/0‚+1‚ü0û \n<ôÛ§.ân0+epâ0ß\00*0+ep!\0Zæä¸#?„Nhğåü]aÿU‘2ø,fíÎ?v’c0(Œq0\r	`†He\00A0\r	`†He\00<(’€ŠÖ%‚µvi‡M};æë÷Îæ“\\¼BàtØòÌªPÈX\0)•£nˆ«Ö”Ã2Û0Q0	`†He*—ğİR\nÖ;èOü=³*4°0™fÍ7ÄÆÙÆ˜8LÌào\"“|×¨uSÍ«=ğ Ue—{¶[¾“[õù&+ØÌ0û \nªæ®\'Šà0+epâ0ß\00*0+ep!\0€ŸÿïİoˆŠ¯w™Ë\"oè©« ëšõ%‘ËÏ\'0(Œq0\r	`†He\00A0\r	`†He\00OJ/x¦¢Æşé´RWmÁá@ƒe«`†cSá¤æ*½ 5;“¼+¨\nÄuËı}š0Q0	`†He*ˆ¬¶N0: vñß™ƒ¨¨0¦p²‘\'æ¨êÃŞNnÇÈq¤¶Ğ/?ÙUPBWšDÜ÷‰ÈT›šåöoß€¯9)0&	*†H†÷\r0	`†He.ŞÏí$\nœ˜Á#ñç¡0\r*†H†÷\r	¢0\00 0\00\r	`†He\02±{¿	”°È!ù\rÛ&ñûbUõÎ§‚¼Üw9-\"!\'½\"¥J	˜©å<æõˆÁ÷’5{dZäxæ‘İ“q÷¥DuÁ9Äòšš«y\Z{`Qb1ÑÈ¤À®D5ÌÅ?(7HíT-ZVĞäµÿÕ‘„œù”0Œç\rºr³ñÆş”wËîÍ\r{h³5:’« $xÓs†K†ÎŞëh0¨ş°U¢Ôëê¬kU÷#±½¸Õ[2\ZS0Q0\r	`†He\0@f°ffnúíñÃºƒ„3›—É¬aŞ‰^–Ïò±L]|\nŒ¯V›úf?¢¢ÉjH·¤°]J¹À« õ'),('be48aa42-e792-4933-8e47-4e5f27910c09','a3010954-066b-4b99-b7c6-ff6bb03e517f','­$be48aa42-e792-4933-8e47-4e5f27910c09\Z$a3010954-066b-4b99-b7c6-ff6bb03e517f\",0*0+ep!\0ã«ÿ·‹€Sc\ZÙx>•gWï»`20~”!ìÈ1†5†*ú0‚v0‚>	*†H†÷\r ‚/0‚+1‚ü0û \nªæ®\'Šà0+epâ0ß\00*0+ep!\0æ¢\n/ÛÍ¹ä¿¾B\'/œlSpÍÛÎ°Ç#x@´´ÛJ¤0(Œq0\r	`†He\00A0\r	`†He\00ïöAÊK	†Z×º·=íJt«¡Ylà™x±OÈîp¥íJnê­¿Ã\0åáx!>ïCÙ0Q0	`†He*¨Ó¾*häéã¹ğõ\n«·0®×Êœ®Ùío»–h™,;ö2Ï!DN3ùz5hŞ…’ôR-™ÖÁ¥£ì¢0û \nØ®THdW0+epâ0ß\00*0+ep!\0;¶‡šÛ£Iˆjv‚˜\'=`„¾ËÓ·ä¬Ë°´Â0(Œq0\r	`†He\00A0\r	`†He\00(y³\'š—‡ï°\Z>Œ.°çáaw·T”MIw·±Ø«”p[èü;«‡”VİGêpî¿0Q0	`†He*ÕÊÒ@,ìŸu:úàv â0O«Ï[¿uˆâ{.¢9Öî?u¤` jXÆ-œ¯§$N(#	SZvNÙyÈiopj±0&	*†H†÷\r0	`†He.º¢ñşÓ™F\nxë¡0\r*†H†÷\r	¢0\00 0\00\r	`†He\02±%É	r%)«%\rs|JûB\"×‰¤êuïP‘¸ÊÁÈ%dÏÖ—?fÜo=¬\nùJ8Ê$ØÖ‰Ç¶d’Qhà2é¥ÙêÉ–	5Š  Z<¿P0Áâ£#O¼}j½­g`Ì÷àB?ÃÅ7İZœF6\nx9z­îÄaÂ`çîl\0øsE†ßóCşµÀ¤€0C¶îæj\Zxãò\0Ğn•JäÜÛU³ŸëëãÍ–:SZP\ZS0Q0\r	`†He\0@Ö6öšz6jØ}¡oğ-úDòÁÂ3\rÉ’R_c¿uCˆœw/•ìKÀ±\\b2D]Å\0—„u|\0ò7GR—·');
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
INSERT INTO `virgil_role_assignments` VALUES ('6fd13117-717c-4bfb-aee9-044a7910005e','66999ad1-2775-41a4-9fbb-96201bc8202b','ˆ$6fd13117-717c-4bfb-aee9-044a7910005e\Z$66999ad1-2775-41a4-9fbb-96201bc8202b\"<ôÛ§.ân*­0‚ˆ0‚?	*†H†÷\r ‚00‚,1ş0û \nØ®THdW0+epâ0ß\00*0+ep!\03Ùe\rŠÇg&ÜÜ¡I²æDÔFˆœ%€Ë¡7,BR[:0(Œq0\r	`†He\00A0\r	`†He\00\rY\ZÛK<`6\n8{w?ªô%èÂ•ÁXš ¹iú¼ü$>§\"”õ˜4ë]›0Q0	`†He*ÕÁf¡6W [\nê±•0½cÀZ÷‹0h(kó-çl:¤O*Êü>B{_Ç\'áo\nÂ%>müi£2kø¢‚0&	*†H†÷\r0	`†He.S£F²®\\ !•¡0\r*†H†÷\r	¢0\0\0  0\00\r	`†He\0£0\n+ƒ¬Ï–¶2én¬”ÜÅŠßñ‹¡ÚÖ‚ºi%,¨Ì-Ò{¾ïKcİ ˆ¦4vÑ›¨oeoEcdÉv,ùÀC6éQ2şÒÁÚ_P²=™ÑÒXÈD?—z‘¤ò¤ÄtòP»ÒÚ bÿ‰lÍ[à5\\Kİ‡ğ8æQÕ‡»1Ê¯ÄœiWùGh®¼²0aœäÔ?u¾ñİy\\gğÄœ±ã‡6c{b ÖİµB¸D^ßêC1	U|M‰«Í`}nä_ÆDÿ&ÿ×Ù¬ñ>ìpb=GV{yZf™dæv­Ö%2í<Ì¨L?ù½;V/CTmS(e®³AL$ÎŞ5=¼ì/u¸…@‹(WœÃñŸŸ|÷\0WFácIÙC\ZS0Q0\r	`†He\0@P6Tn>š»3…(9”fÄìfû8Ñ¹§}ÖzòÛNıúõEk¶¯,æ.Øò=ÏšÅË1Ç:ª´KGG\nå€');
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
INSERT INTO `virgil_roles` VALUES ('6fd13117-717c-4bfb-aee9-044a7910005e','V$6fd13117-717c-4bfb-aee9-044a7910005e\Z,0*0+ep!\0\\Ë¢úUÊAíĞ£R²x3ç]1k‚8×İì—>ş<Ï2“\ZS0Q0\r	`†He\0@MWà0bêIDßÊÇ¶™Nø®ˆ>-8OºäU SGHüÿô~¾k5Àpæ]ºÜ$PàÓ‘ÁÆ]Ò8ù$');
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
INSERT INTO `virgil_users` VALUES ('66999ad1-2775-41a4-9fbb-96201bc8202b',2,'®\r$66999ad1-2775-41a4-9fbb-96201bc8202b\Z M€sìÍÇZyİ“Ø€¡„‰ˆŒÑ«ÑÿDüÁJÇ‰Qµn\" °ùl7#ÊgAŠƒr7vÕ¬(!ƒú5ş‘üÆØô0ó6Ä*,0*0+ep!\0Ş“rÓDexÄQ~è‘^Eìø“øld™Ş\r1ßÔ!ÃÌÏK2`}Ë(¾›¡	lf“‰*ãPHULiµm¶nnø€ŞßfÜF_Ig	³ük¢	Éı.-Ùg¡wôÀ.€›Ÿ  ğ16¢{L¹€dAŠ\0­Ô0ÊoÊ;ã3¹#f˜Uå»:­0‚ˆ0‚?	*†H†÷\r ‚00‚,1ş0û \nvY´úôË<b0+epâ0ß\00*0+ep!\0™²Ñ†š»\"“‚¨‹°²CÙI’w¯LS¬“©/Í¦0(Œq0\r	`†He\00A0\r	`†He\00h‹“·ŠÜ×\0çı•–¹ÿÊç°Â¹åR.èC«}hıÿªp¸_+:5ÙÈ_.0Q0	`†He*ér.XE&Ä‹ñ~“ê­Ì‡E0LU‹’‹ê ZpPM)MN™´ó¬AÚÔÄ@¹‡ùMU2¯—ŞºK`¼ÔmxËS5,vËá0&	*†H†÷\r0	`†He.R	t?ç»¢ğy‘¡0\r*†H†÷\r	¢0\0\0  0\00\r	`†He\0£0\n+ƒ¬D¸q&ä–­õ(å	¯Å^™F‡}€‡G£j,±¿ôæ®œ/”«øé3†n:\r4î¡ï/>Ï¾¶øı/[Ã¤lŸ9å1zÁÒÖ,\nŸè¿sïá»©ê+vŞ$=[Ò¤¶|Wg œqÊ¯ùøÍ®íêuêåyıÀúå~ˆ(şpxTVì#ÈZûS7–ä,Y8Ø“Ò÷Ö¨\0ç_°g…²yş Ìõ—›$F‰äqØüåF‘Á)JÅw@@ÊÕS¬âró|:éYĞÌc‡ŞÿIEÅßOÈk@ç±Ûí\0`£]Ô£¾H—§PnuÙp\\.J}¥«k—n2OÎÒvbÏü5÷‚[.ÏâW¼aãäB­0‚ˆ0‚?	*†H†÷\r ‚00‚,1ş0û \nvY´úôË<b0+epâ0ß\00*0+ep!\0L¬úº}Á¿¿\0Hw<;‹hP9`@¨Ğ} Ï$0(Œq0\r	`†He\00A0\r	`†He\00®…ƒÊš™©Ë*Ä4kÕ`Ë1…E›ı€\n;ÒãÂa×l»Twœ9$OˆÙ0Q0	`†He*lJ2‡É©ºÈ«q¸“‘0ÁÌ¥™½ÅŸ¥aÏBár>ıÓî¡$¢!©Oi|Aì5ãèºéiäÉ‰<˜dÇÔùê,0&	*†H†÷\r0	`†He.$¥+ÀhÒµµÁÍ¡0\r*†H†÷\r	¢0\0\0  0\00\r	`†He\0£0\n+ƒ¬UèWc¶O›z(T1Å¦KğN9œã\n™4hĞ^ëşÚ•ôOmÀ‡y»N~r¡îbÇL›–§êKZl”ŠŒ6¼±W\Z¼‹æwFÄ(Pînwï5ëgîs¸[ÀB/Î	\'¯9ËŒÑ“`Âp7¢ä¢×I¢µl‹8i“ÙS+İş±\\n<œmâ—$EÃì†°ØîÃ>³\'İ­·M>å#âŸš?ts¢Ÿ˜ĞnÏWğhlø½Oh0ÈƒÃñr#Bò÷NtÖ1ÇƒbÕÁëA—•Õw è	wïİaÎ\\+_/#<£™Ë£]ÿIDßy´\rz¯ey\"a¦Ÿ”¬^Ì¬%…¦êøĞ¶nÌJxm;âFÔ‰]W¼DH@‚ÿ!şˆRq[ÈJPÿ+g?R&ö²À¯Á‡´ò±Â*FŸ®#5GÑ}\n«k™a|.°aí•…wŠÒÆ²—®.ãìÖµî¿w¿ã.£ãô)FÏædÅä.¯)Ë¢ @\ZS0Q0\r	`†He\0@æÉVw´bÌ[‚1×$¨¶ù±ºîš¿\nf‰m!A¸‰rRãæğ‘Æq4¥ªÍ<?-*å{Êñ7LR…ô\"AoÚT4?„`\Z¤@²şEtãa÷{Mb×~İ ÈÔ(\'AóHØàEïÒßÉ»o>P=hD|KÖøß)¸Ú±u*A¶Y{®oÔù\rD<!õıoùòµlÅ!âsKİÈxA|ô3HØĞqdá\'7AAÂv‹ıY;Iã¦#Ë÷[†²†0:A`´ÇF%ÔúR0²ìÀÇğ¿TğQ_Ãç!*9(Q9ôùÊ{ı¡n½ÄM°4*NğÄDNìÛÊ\"-.à/ÿ'),('be48aa42-e792-4933-8e47-4e5f27910c09',2,'®\r$be48aa42-e792-4933-8e47-4e5f27910c09\Z Ÿß(\\xÅÜjXG µ\n!ĞL…‰«{¨	hä¨¦òã\" å¶åˆg~w¹Íì³mÑ]¡.‚-q±ŞùNãorgŞr*,0*0+ep!\0@Ídrn\nwù¼CÊH.Mæ]¿iÿ~Ë¨ˆB”[Ö—¬2`¦)\\	ıûü<·]1’¸…rÇ÷]a1ÛR*‘–é2éc½X¦oƒü`ºüj\ZOìÜh.É“ Y’1¿Ø¨õ\r™\rkÅO\Z+¸§\Zş)y[Š}±%¸\\	HÀi:­0‚ˆ0‚?	*†H†÷\r ‚00‚,1ş0û \nvY´úôË<b0+epâ0ß\00*0+ep!\0½Ìh¼†ªÍhü;±éì˜\'öÙpÍ4â\"ïë0(Œq0\r	`†He\00A0\r	`†He\00©ú‚\Z,0/Ø¯pjŠÀÌ\"\ZvMÉn+¨Bä¬·ñ0›^²L5G„o*´0Q0	`†He*Ó7Ë\0J—Àİp÷@W0ŠÈ@ŒÇ˜ïŸÎ75‚v‰—8…6ô„©úˆÕ5ıOÑ•-i” ­³\'–77m0&	*†H†÷\r0	`†He.ÔBëäÔ-3­ ‘¡0\r*†H†÷\r	¢0\0\0  0\00\r	`†He\0£0\n+ƒ¬İOßìß`kìÕ8ÁÄÚ£¬>÷hHÇé!§ÜÒğÒC `ˆ\\ÁØ/‰\'Î/¹€¹Uê<O²¬¬ŒèT—ª¿(ÎötõÊ\0™pš*¨DôÎ­?ôd&+\\\0xù$9ñp‰½q|fÍp‰$tÉŠŸˆIé¤‚~\rŞ>Ò‘8HÏ,(’1$<ìŠ¢ûÅJvk™¾Ùó…öR×l]°$n²ùN›W\\ù\\Ğ:ÒHå˜á×+@úd\n­[ß4jú¶·ü8.;$v¥ˆ­Êç^FäşÌîäñ>uEìZÒj¡§Ç¬Ôwx&‰HlË]×Ûöz€“¥)f ëƒ¬ES.\\*€Ø<”‡ÿG!Ä0ª³Ë9İet~`\0²È6‰nVœB­0‚ˆ0‚?	*†H†÷\r ‚00‚,1ş0û \nvY´úôË<b0+epâ0ß\00*0+ep!\0•şõœÊ°R„€–ú£K Ìbz{˜(Pç…ˆ@¾Ş¸0(Œq0\r	`†He\00A0\r	`†He\00náç“·lÚ,N2OZzp”®Ç·ª±•-ıÏm`Äæ=6áy ”ßĞÆqË†0Q0	`†He*Ííáàè“¼ûûyÇÖ0ÜçŞÏSÜc.&!\nÖõÕ¤Qˆ„Ò^µwç±R·mµ-WK·ôæå3O}0&	*†H†÷\r0	`†He.‰ñu#VOõ%€¡0\r*†H†÷\r	¢0\0\0  0\00\r	`†He\0£0\n+ƒ¬|\nıp\"õè¹v¨5)~;µôÆÆÓ\'Y9!»Ö6ÜMì@Ó‘Ã ñºNû—×˜[Ö»©€¿¹Òé¡v=›óZtÈ˜/å,×RÉ68ØYB~7†g|r¤·áı½ånfß†wíÊÛ-ÆLßÀ:Ì-x¤lDD÷2Ó¹ùs™.ÚJ1û«ÉAÑú5eï5ÎˆßUÚdğô}#Ş×ô²{t›>Ğ°êÖ]8LæßH\nÂ8üÒèëØÜª!²Ä…¡DV~ùlB‡ÉÁá\'¿á~\'ÇÃw¶LÈô·ü(Ï^¤ªÇDfşÖ9Qlcuâ–ß\r*äQî· jÏä/ogkyaüÁ€€_kz¸vÇï³Š ¦Ê1%&ÚãaAJ\0wÚ=JP«ãZÍúâY}áÇİ35ÆèëîH\ZŞ-lÚwğ<Ñ‚€„6¸OüÁÊ˜-_?X§…Œ¥.‹œOLn8›M«Od‘Ì	f§£Ê%a/\ZS0Q0\r	`†He\0@µû+¯GPkÅ>¯g)şÍÛØŒÎ‚\Z*t´õ­k=Òö š-¹ì?*«(˜ƒM%ÆÙ–¤rLoÔ“\"A?_Öj0·¯‡ŒgIC¼¹Œí:ñÂ¾¤ôºû:ß_è?õÛ¦Ôk}i›ÖÉÂüUµœ^€¦bW& ´*Abä„$\\Knçfûë;äÔ¯ÔŒ„;(?ü‚¹_ø¡Å½TJ•œc¤¦ÕÖ¹ç˜±5U„ãLmÀø|›Øo]0:AçØë\rÿ“•azç_Ö¦Ã&Ïç\'‹Nò\ZÍÂrò>Üt\\\\b‚<åç\\ÜÈ‹İ2hì–pÎæä¡ş^üû‡QËEZ');
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

-- Dump completed on 2020-02-20 10:52:25
