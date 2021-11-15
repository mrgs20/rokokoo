---
layout: default
title: Rokokoo
description: SELVITYS ROS-ROBOTTIEKOSYSTEEMISTÄ 
---

<!-- Text can be **bold**, _italic_, or ~~strikethrough~~.

[Link to another page](./another-page.html).

There should be whitespace between paragraphs.

There should be whitespace between paragraphs. We recommend including a README, or a file with information about your project. -->

# Johdanto

Vuoden 2019 lopussa maailma kohtasi maailmanlaajuisen COVID-19-pandemian. Pandemia on levinnyt hälyttävällä nopeudella ja taloudellinen toiminta on lähes pysähtynyt maiden asetettua tiukkoja liikkumisrajoituksia. Maailman kokema taloudellinen shokki on suurin vuosikymmeniin. Marraskuussa 2020 julkaistun Satakunnan-talous katsauksen mukaan 2020 keväällä joka 20.s työpaikka katosi. Satakunnan talouden tila oli kuitenkin alkanut heiketä jo aiemmin. Pandemia on siis syventänyt jo alkanutta taantumaa. Koko teollisuuden liikevaihto laski 3,3 %, viennin arvo laski 5,1 % ja henkilöstömäärä supistui 4,1 %.  Automaatio- ja robotiikka-alojen liikevaihto putosi 5,5 % vaikka henkilöstömäärää lisättiin 4,5 %.  Supistusta on kuitenkin tapahtunut selvästi vähemmän kuin Suomessa keskimäärin. Merkkejä talouden elpymisestä on kuitenkin jo nähty kuluvana vuonna 2021. OECD:n taulukosta yksi nähdään Suomen ennustettu palautuminen pandemiaa edeltävälle tasolle. (The Global Economic..., 2020; Vähäsantanen, 2020.)

![Taulukko](/assets/images/OECD.png)
##### Taulukko 1: Palautuminen pandemiaa edeltävälle tasolle (The OECD Economic Outlook, 2021)

Satakuntaliiton keväällä vuonna 2017 tekemä seutukierros Satakunnan kunnissa kertoo kuntien painottavan koulutusta, saavutettavuutta sekä kasvun mahdollisuutta. Kyselyssä nousivat esiin koulutuksen saatavuus, koulutuksen ja työvoiman kysynnän vastaavuus sekä korkeakoulutuksen turvaaminen ja kehittäminen. (Satakuntaliitto, 2017) Robotiikan koulutus kasvuyritysten ohjenuorana- hanke paneutuu kuntien esille nostamiin seikkoihin ja auttaa omalta osaltaan luomaan uutta osaamispääomaa ja levittämään sitä ajan myötä koko Satakuntaan. Hankkeessa kehitetty ROS-robottiekosysteemiin keskittyvä täydennyskoulutuskokonaisuus tuo merkittävän lisän alueen aikuiskoulutustarjontaan. Vastaavaa täysin maksutonta koulutusta ei Suomessa ole tarjolla. Muuntuvilla robotiikkaratkaisuilla luodaan yrityksille kaivattua kustannustehokkuutta sekä helpotetaan robotiikan kehittämistä tekemällä siitä nopeampaa ja yhteisöllisempää. Hankkeessa käytetty SAMK (Satakunnan ammattikorkeakoulu) Yhteistyö Moodle on sähköinen koulutusalusta, joka mahdollistaa ajasta ja paikasta riippumattoman opiskelun, jolloin opiskelijat eivät ole sidottuja pendelöimään oman asuinalueensa ja Porin korkeakoulujen välillä. 

Robottikäyttöjärjestelmän kehittäminen edellyttää järjestelmien suunnittelutekniikoiden perusteellista tuntemusta, suunnittelutavoitteiden tuntemusta ja tiukkojen kehitysprosessien noudattamista. Avoimen lähdekoodin robotiikan syntyminen on mahdollistanut robotiikan kehittäjien ja toteuttajien omien robotiikkajärjestelmien kehityksen. Nämä perustuvat sisäisiin taitoihin sekä julkisesti saatavilla oleviin robotiikan väliohjelmiin, simulaattoreihin, kirjastoihin ja työkalupakkeihin. ROS:in suosio perustuu laajaan yhteensopivuuteen ja toimivuuteen muiden avoimen lähdekoodin hankkeiden kanssa. (Petrara, 2019.)


# Robot Operating System, ROS

Vuonna 2007 Stanfordin Artificial Intelligence laboratoriossa ja Willow Garagen avustuksella kehitetty Robot Operating System (ROS) edustaa avoimen lähdekoodin politiikkaa ja on siten muodostunut yhdeksi suosituimmista ohjelmistokehyksistä robotiikassa. Se on suunniteltu hajautetuksi ja modulaariseksi, jotta käyttäjät voivat käyttää ROS:ia tarpeidensa mukaan. ROS-ekosysteemissä on yli 3 000 pakettia ja siinä on laskettuna vain ne, jotka ovat ihmisten julkistamia. ROS tukee mobiili-, teollisuus-, kirurgia- ja avaruusrobotiikkaa sekä autonomisia autoja. ROS on eräänlainen aarreaitta täynnä algoritmeja, ohjelmistoja, ajureita, toimintoja ja paljon muuta. ROS:in joustavuus pohjautuu sen kykyyn toimia informatiivisena perustana innovatiiviselle kehitykselle. Muokattavuutensa vuoksi ROS mahdollistaa käyttäjien omien suunnittelumallien käytön. Käyttäjäyhteisönsä jatkuvan kehittämisen ja lähdekoodin avoimuuden vuoksi ROS:in käyttö koetaan turvallisena ja luotettavana. (Is ROS For..., n.d.; Vozel, 2019.)

![Taulukko](/assets/images/Kasvuodotukset.png)
##### Taulukko 2: ROS kasvuodotukset vuoteen 2027 (Research and Markets, 2021)

ROS markkinoiden odotetaan kasvavan vuoden 2020 arvioidusta 216,6 M$:sta tarkistettuun 356,8 M$:iin vuoteen 2027 mennessä (Taulukko 2). Sen vuotuinen CAGR (Compaund Annual Growth Rate) tällä aikajaksolla olisi täten 7,4 %. COVID-19 pandemian aiheuttaman ekonomisen kriisin vuoksi CAGR:in on arvioitu tippuvan 7,1 %. Tutkimus- ja kehitystyöhön liittyvät teollisuus automaation varat, yhteistyössä toimivien modulaaristen robottien lisääntyvä käyttö sekä RaaS (Robotics-as-a-Service) kasvava kysyntä ennustavat edullisten ROS teollisuusrobottien käyttöönottoa. (Markets and markets, 2019; Research and Markets..., 2021.)
<p>&nbsp;</p> 

## ROS 1

Kun lähdetään toteuttamaan uutta robottisovellusta, on viestintäjärjestelmä yksi ensimmäisistä tarpeista. ROS:ia käytetään monissa robottiympäristöissä ja monien antureiden, ohjaimien ja moottoreiden on kommunikoitava keskenään, lähetettävä ja vastaanotettava tietoja haluttujen tehtävien suorittamiseksi. ROS:in sisäänrakennetulla ja hyvin testatulla viestintäjärjestelmällä säästetään aikaa ROS:in toimiessa hajautettuna arkkitehtuurina, joka käyttää julkaisija/tilaaja (engl. publisher/subscriber) -viestejä solmujen (engl. node) välillä. Jokaisella solmulla on yksi, tai useampia aiheita (engl. topic) tai palveluita (engl. service), jotka ovat irtautuneet ja joita voidaan käyttää uudelleen. Esimerkki julkaisijasta on 3D-kamera, joka tuottaa striimattua kuvadataa, ja tilaajana on tiedon käyttäjä. Palvelu puolestaan on asiakas/palvelin malli, jossa käytetään pyyntö/vastaus viestejä. Esimerkkinä voidaan käyttää kuvatietoja, jotka muotoillaan toiseen muotoon ja saatu vastaus saadaan pakattuna datana. ROS-viestinnässä käytetään kuvan yksi esimerkin mukaista tapaa solmujen välillä, missä Talker on julkaisijana ja Listener on tilaajana. ROS master edesauttaa aiheita löytämään toisensa. Tätä kutsutaan sentraaliseksi viestinvälitykseksi, jossa kommunikaatio alustetaan ja jonka jälkeen jokainen aihe voi kommunikoida suoraan keskenään. Näiden viestirajapintojen rakenne on määritelty IDL-sanomassa (Interface Description Language).  (Core Components, n.d; DiLuoffo, et al., 2017.) 

![ROS1](/assets/images/ROS1.png)
##### Kuva 1: ROS viestintä (DiLuoffo, et al., 2017)
 
Julkaisija/tilaaja järjestelmän ollessa anonyymi ja asynkroninen voidaan dataa tallentaa ja toistaa ilman mitään muutoksia koodiin. Rosbag record tilaa aiheet ja kirjoittaa niistä bag-tiedoston, jossa on kaikki julkaistut viestisisällöt. Tiedosto sisältää lomitetut ja sarjoitetut ROS-viestit, joista on suoraan tehty yksi tiedosto niiden tulohetkellä. Tämä on tehokkain ja levy ystävällisin tallennusmuoto. Bag-tiedostoa luodessa voidaan tiedosto vielä pakata, jolloin säästyy levytilaa. (Core Components, n.d ; rosbag/Commandline, 2020.)

ROS 1 käyttää Cpp:lle roscpp:tä ja Pythonille rospy:ta. Se tukee Python 2:sta. Kirjastot ovat täysin itsenäisiä ja ne on rakennettu tyhjästä, tarkoittaen sitä, ettei ohjelmointirajapinta niiden välillä välttämättä ole sama, jolloin niiden ominaisuudet on kehitetty vain toiselle. ROS 1 ei ole varsinaisesti mitään rakennetta, miten kirjoittaa solmujen toiminnallisuus ja jokaisen toteutus voi olla ainutlaatuinen. Käynnistystiedostojen kirjoittamisessa käytetään XML:ia (Extensible Markup Language). ROS 1 käynnistetään aina ensin ROS-isäntä, roscore, joka toimii solmujen DNS-palvelimena (Domain Name System), jotta ne voivat hakea ja tunnistaa toisensa. Palvelut ovat synkronoituja mikä tarkoittaa sitä, että pyyntö on jumissa, kunnes palvelin joko vastaa tai epäonnistuu. Solmut rakennetaan käyttämällä catkiniä, joka on ROS:in virallinen rakennusjärjestelmä ja alkuperäisen rosbuildin seuraaja. (catkin/ conceptual_overview, 2020; The Robotics Back-End, 2021.) 

Väliohjelmiston pääkomponenttien lisäksi ROS:lla on tarjolla robottikohtaisia kirjastoja ja työkaluja, joilla robotti saadaan nopeasti toimintavalmiiksi. Tässä niistä muutama: 

-	Robottien vakioviestimääritelmät
-	Robotin geometria kirjasto
-	Robotin kuvauskieli
-	Ennakoitavat etäsuoritukset
-	Diagnostiikka 
-	Asento arviointi
-	Paikannus
-	Kartoitus
-	Navigaatio

(Core Components, n.d)

ROS:lla on aktiivinen tukijoukko, johon kuuluvat mm. käyttäjät, ROS ytimen ja pakettien kehittäjät sekä työkalujen ylläpitäjät. He kuuluvat joko vapaaehtoisiin tai Open Source Robotics Foundation:in työntekijöihin. ROS:lla on oma Stack Overflown tyylinen Q&A nettisivusto, ROS Answers 13. Moni käyttäjä kokee tämän olevan luotettava ongelmienratkaisukanava. Pakettien ylläpitäjät ja yhteisöpäälliköt käyttävät postituslistoja ilmoituksiin kuten tärkeät korjaukset tai julkaisut. Helmikuussa 2016 avattiin ROS Discource foorumi, jossa voi keskustella ROS:sin tulevaisuuteen liittyvistä asioista. Sivusto on kohdistettu lähinnä kokeneemmille käyttäjille, pakettien ylläpitäjille ja yhteisöpäälliköille. Suurin osa paketeista löytyy kuitenkin GitHub-alustalta. (Estefo, et al., 2019.)

Uusin ja viimeiseksi ROS 1 distribuutioksi jäävä 2020 julkaistu Noetic EOL (End of Life) päättyy 2025. Viimeisen ROS 1 versioon päätavoite on tarjota Python 3 tukea kehittäjille ja organisaatioille. (The Robotics Back-End, 2021.)  
<p>&nbsp;</p>  

## ROS 2

Alfa-koodina alun perin ilmestynyt ROS 2 otettiin käyttöön vuonna 2014. Alpha code 3Q2015 versio ei kuitenkaan täyttänyt vaadittuja turvatoimia. Tämän vuoksi kehitettiin seuraajaversio: ROS 2, joka käyttää erilaista lähestymistapaa viestintäkerroksissa ollen nyt OMG:in (Object Management Group) teollisuusstandardi DDS (Data Distribution Service). ROS 2 on alun hankaluuksien jälkeen julkaistu jo monta versiota (Kuva 2). (Basheer & Varol, 2019; Maruyama, et al., 2016.) 

![ROS2_Distribution](/assets/images/ROS2_Dist.png)
##### Kuva 2: Luettelo ROS 2 julkaisuista. (New Version of..., 2021)

DDS turvallisuusspesifikaation laajennus julkaistiin 2016. DDS käyttää IDL-määritystä, jonka OMG määritteli sanomien määrittelyyn ja sarjoitukseen. Sen ydin on DCPS (Data-Centric Publish-Subscibe) joka on suunniteltu tarjoamaan tehokas tiedonsiirto jopa hajautetuissa heterogeenisissä alustoissa. Oletuksena oleva hakujärjestelmä on hajautettu etsintäjärjestelmä, joka sallii minkä tahansa kahden DDS-ohjelman kommunikoida ilman ROS masteria ja joka täyttää turvallisuutta, joustavuutta, skaalautuvuutta, vikasietoisuutta ja turvallisuutta koskevat vaatimukset. Moni DDS-toimittaja tosin tarjoaa vaihtoehtoja staattiselle etsinnälle, joten dynaamisen etsintämekanismin käyttö ei ole välttämätöntä. (DiLuoffo, et al., 2017; Maruyama, et al., 2016; Woodall, n.d.)

DDS:ää on käytetty monipuolisesti eri asennuksissa kuten: 

- taistelulaivoissa
- suurissa hyötylaitoksissa kuten padoissa
  - rahoitusjärjestelmissä
  - avaruusjärjestelmissä
  - lentojärjestelmissä
  - junien vaihdejärjestelmissä
- sekä monissa muissa skenaarioissa


Sen johtospesifikaatio DDSI-RTPS, toiselta nimeltään RTPS (The REAL-time Publish-Subscibe Protocol) on joustavuutensa vuoksi käytettävissä luotettavaan, korkean tason järjestelmäintegraatioon sekä reaaliaikaisiin sovelluksiin sulautetuissa laitteissa. DDSI-RTPS korvaa ROS 1:sen TCPROS- (Transmission Control Protocol) ja UDPROS (User Datagram Protocol) johdinprotokollat julkaisuille ja tilauksille. (Woodall, n.d.)

Jotta DDS:stä voisi tulla ROS 2:sen toteutuksen yksityiskohta on kaikki DDS-spesifiset ohjelmointirajapinnat ja sanomamäärittelyt piilotettava. DDS tarjoaa etsinnän, viestin määrittelyn sekä julkaisu- ja tilausliikenteen. ROS 2 tarjoaa vastaavanlaisen käyttöliittymän kuin ROS 1, jolloin suuri osa DDS:n monimutkaisuudesta olisi piilotettuna osalta ROS-käyttäjiä tarjoten erikseen pääsyn DDS-toteutukseen käyttäjille, joilla on äärimmäisiä käyttötapauksia tai joiden tarvitsee integroitua muiden olemassa olevien DDS-järjestelmien kanssa (Kuva 3). (Woodall, n.d.)

 ![ROS2](/assets/images/DDS ja ROS API.png)
##### Kuva 3: DDS ja ROS API (Application Programming Interface) pohja (Woodall, n.d.)
 
 DDS-toteutuksen käyttöön tarvitaan lisäpaketti, jota ei normaalisti ole käytössä. Pakettiriippuvuuksien avulla selvitetään, onko paketti sitonut itsensä tiettyyn DDS-myyjään. ROS:lle on tulossa yksi parhaiten tuettu DDS-toteutus, jonka avulla voidaan löytää ratkaisuja reaaliaikaisiin ympäristöihin ja pieniin sulautettuihin järjestelmiin vähentämällä kirjastojen kokoa ja muistijälkiä. (Woodall, n.d.)

 ![ROS2](/assets/images/ROS1_ROS2 arkkitehtuuri.png)
##### Kuva 4: ROS 1 / ROS 2 arkkitehtuuri (Maruyma & al., 2016)

ROS 2:ssa on enemmän kerroksia kuin edeltäjällään (Kuva 4). Peruskirjastoja on vain yksi, C:llä toteutettu rcl (ROS Client Libraries). Tämä sisältää kaikki ROS 2 ydinominaisuudet. Kirjastoa ei käytetä suoraan ohjelmissa vaan siinä käytetään toista asiakaskirjastoa, joka on rakennettu rcl:n päälle. Kehittäjille tämä tarkoittaa siis sitä, että muiden asiakaskirjastojen luominen ja käyttö on helpompaa ja tarvitsee tehdä vain C-sidos rcl:llä. Oletusarvoisesti käytetään Cpp 11:tä ja 14:ää ja suunnitelmissa on myös Cpp 17. Nämä uudet Cpp-versiot omaavat hyödyllisiä toimintoja, joilla kehityksestä tulee helpompaa, nopeampaa ja turvallisempaa. Solmuja kirjoitettaessa on luotava luokka, joka perii solmuobjektin esim. rclcpp::Node Cpp:ssä ja rclpy.node.Node Pythonissa. Python versioista on käytössä vähintään 3.5. Luokassa on kaikki ROS 2 funktionaalisuudet. Nodelettien toiminnallisuus on sisällytetty ytimeen ja sitä kutsutaan komponentiksi. Käynnistysohjelmien kirjoittamiseen käytetään Pythonia. On myös olemassa ohjelmistorajapinta, jonka avulla voidaan käynnistää solmut, hakea määritystiedostoja, lisätä parametreja jne. Halutessaan voi toki käyttää myös XML:ia, mutta Pythonia suositellaan käytettävän sen modulaarisuuden ja suuremman dokumentaatio määrän vuoksi. ROS 2:ssa ei enää käytetä ROS-isäntää vaan jokainen solmu kykenee löytämään muut solmut itsenäisesti. Käynnistys onnistuu, oli isäntää tai ei. Tämän avulla voidaan luoda täysin hajautettu järjestelmä. Globaaleja parametrejä ei enää ole, vaan jokainen parametri on solmulle spesifi. Palvelut ovat asynkronisia. (The Robotics Back-End, 2021.)

ROS 2 mukana tulee QoS (Quolity of Service) jonka avulla voidaan valita miten solmut käsittelevät viestintää. Halutaanko vastaanottaa kaikki viestit vai päivitetäänkö tietoja usein, jolloin voidaan menettää joitakin viestejä. QoS on ROS 2:ssa oletusarvona, joten siltä voidaan olettaa samaa käyttäytymistä kuin ROS 1. Vain tilauksen jälkeiset viestit julkaistaan ja TCP takaa viestien toimituksen. Mikäli joudutaan käyttämään heikkoa langatonta verkkoyhteyttä tai suurta kaistanleveyttä, on QoS paikallaan. Aloittelijalle tai yksinkertaiselle sovellukselle QoS ei ole ensisijainen valinta. ROS 2:ssa ei enää rakenneta solmuja catkinillä vaan siihen käytetään Amentia, jonka mukana tulee colcon (collective construction) komentorivityökalu, jolloin kääntämiseen käytetään ”colcon build” komentoa. Syy nimen muuttamiseen on, ettei sen haluttu olevan ristiriidassa catkinin kanssa ja aiheuttavan siten sekaannuksia olemassa olevien catkin dokumentaatioiden kanssa. Ament koostuu muutamasta tärkeästä varastokirjastosta, jotka kaikki ovat ament GitHub-organisaatiossa:
-	ament_package paketti
-	ament_cmake varastokirjasto
-	ament_lint varastokirjasto
-	build työkalut
Uutta ROS 2:ssa on myös se, että sitä voidaan käyttää Ubuntun lisäksi myös MacOS:ssa ja Windows:ssä.

(About the build..., 2021; The Robotics Back-End, 2021.) 

Yksi suurimmista eroista ROS 1 ja ROS 2 välillä on simulaatiokyky. ROS 1:llä on Gazebo ja siinä muutamia simulaatiomahdollisuuksia, mutta integrointi on hankalaa ja Gazebo itsessään melko monoliittinen. Ignition Gazebo ja ROS 2 taas puolestaan tarjoavat täydennetyn robotin ja täysin toimivan dynaamisen ympäristön. Erilaiset kilpailut, kuten DARPA SubT (DARPA Subterranean Challenge), RobotX Challenge ja AWS JPL Open Source Rover Challenge ovat osoittaneet, että malli on onnistunut. Gazebon nykyinen versio on nimeltään Ignition Citadel ja sillä voi simuloida fysiikkaa, ympäristörajoituksia sekä antureita. Siihen on kiinnitetty kaikki ROS-elementit, eli mikäli simulaatiossa on virtuaalikamera ja virtuaalinen LiDAR (Ligth Detection and Ranging) eli lasertutka, ovat saadut numerot melko samanlaisia, kuin mitä ne olisivat todellisessa maailmassa. (Quetzalli, 2020.)

ROS 1-koodipohjan siirto ROS 2:seen onnistuu yhteensopimattomasta kommunikaatiosta huolimatta ROS 1-bridge-pakettiadaptaatiolla. Siirron voi suorittaa aluksi muutamalla paketilla ja vähitellen lisätä yhä enemmän paketteja, kunnes ROS 1:ssä ei ole enää paketteja jäljellä. Sovellus toimii odotetusti koko siirron ajan. (The Robotics Back-End, 2021.)
<p>&nbsp;</p> 

### micro-ROS
Mikro-ROS on räätälöity erityisesti sulautetuille ja resurssirajoitteisille alustoille kuten mikrokontrollerit. Suurin osan ominaisuuksista ja arkkitehtuurista periytyy ROS 2:lta yhdistäen saumattomasti ’makro’ ja ’mikro’ robotiikan. Se toimii RTOS:ssä (Real-Time Operating System) ja käyttää DDS-väliohjelmistoa Micro XRCE-DDS (eXtremly Resource Constrained Environment) (Kuva 5), eli DDS:ää äärimmäisen resurssirajoitetuissa ympäristöissä. Käytettävissä on tehokkaita kehitystyökaluja kuten täydellinen koontijärjestelmä eri laitteistoalustoille ja koko robottiohjelmien joukko, joka on saatavilla ROS 2-ympäristössä. Yksi hyödyistä siirryttäessä vähemmän resursseja vaativiin robotiikkasovelluksiin on kustannusten aleneminen, jolloin se on erityisen kätevä teollisen massatuotannon kilpailukyvylle. (Competitive Warehouse Automation..., 2020; XRCE-DDS, 2021.) 

![mikro](/assets/images/Micro_ROS.png)
##### Kuva 5: Micro-ROS:in arkkitehtuuri. Tummansiniset kerrokset ja komponentit on kehitetty mikro-ROS-laitteille. Vaalean siniset kerrrokset rmw ja rlc uudelleenkäytetään ROS 2:sta. (Lange, 2021) 

Seitsemän keskeistä ominaisuutta tekee mikro-ROS:sta käyttövalmiin mikrokontrolleripohjan erilaisiin robottiprojekteihin.

- *Optimoitu asiakasrajapinta, joka tukee kaikkia tärkeimpiä ROS-konsepteja*<br>
  Mikro-ROS:in avulla kaikki solmut, julkaisu/tilaus, asiakas/palvelu, solmukaavio jne. tuodaan MCU:lle (Microcontroller Unit). Asiakasrajapinta perustuu vakio-ROS 2 rcl-kirjastoon sekä sarjaan laajennuksia ja soveltuvuustoimintoja (sclc). Näiden yhdistelmä on optimoitu MCU:lle. (Features and Architecture, 2021.)
- *Saumaton integrointi ROS 2:n kanssa*<br>
  Mikro-ROS agentti yhdistää MCU:in mikro-ROS-solmut saumattomasti ROS 2 järjestelmiin mahdollistaen näin pääsyn mikro-ROS-solmuihin ROS 2:sta tunnetuilla työkaluilla ja API:lla tavallisten solmujen tapaan. (Features and Architecture, 2021.)
- *Erittäin resurssirajoitettu mutta joustava väliohjelmisto*<br>
  eProsiman Mikro XRCE-DDS täyttää kaikki sulautetuille järjestelmille asetetut vaatimukset. Ajon aikaisten muistin allokointien välttämiseksi ROS-väliohjelmiston rajapinnassa otettiin käyttöön staattiset muistivarastot. (Features and Architecture, 2021.)
- *Multi-RTOS-tuki yleisellä koontijärjestelmällä*<br>
  Mikro-ROS tukee kolmea avoimen lähdekoodin reaaliaikaista käyttöjärjestelmää (RTOS): FreeRTOS, Zephyr ja NuttX. Se voidaan siirtää mihin tahansa POSIX-käyttöliittymän omaavaan RTOS:iin. ROS 2-pakettina toimitettavaan asennusohjelmaan on integroitu RTOS-spesifiset rakennusjärjestelmät. Näin ROS-kehittäjät voivat käyttää tavallisia komentorivityökaluja. (Features and Architecture, 2021.)
- *Lupalisenssi*<br>
  Mikro-ROS kuuluu samaan Apache License 2.0 lisenssiin kuin ROS 2. Tämä koskee mikro-ROS-asiakaskirjastoa, väliohjelmistokerrosta sekä työkaluja. RTOS projektia luotaessa on otettava huomioon ROS-projektin tai toimittajan lisenssit. (Features and Architecture, 2021.)
- *Vilkas yhteisö ja ekosysteemi*<br>
  Jatkuvasti kasvava, itseorganisoitunut yhteisö on kehittänyt mikro-ROS:in ja sitä tukee virallinen ROS 2-työryhmä, Embedded Working Group. Yhteisö jakaa aloitustason opetusohjelmia, tarjoaa tukea Slackin ja GitHubin kautta ja tapaa kuukausittaisissa julkisissa Working Group-videopuheluissa. Yhteisö kehittää myös työkaluja mikro-ROS:in ympärille. Esimerkkinä MCU-laitteistolle kehitetyt benchmarkkaustyökalut, joiden avulla voidaan tarkistaa muistin käyttö, suorittimen ajankulutus sekä yleinen suorituskyky. (Features and Architecture, 2021.)
- *Pitkäaikainen ylläpito ja yhteentoimivuus*<br>
  Pitkäaikaisen ylläpidettävyyden takaamiseksi mikro-ROS-spesifisen koodin määrää minimoitiin käyttäen avoimen lähdekoodin RTOS:ia, standardoitua väliohjelmistoa sekä vakio ROS 2 Client Support kirjastoa. SOSS (System-Of-Systems Synthesizer), nopea ja kevyt OMG DDS-XTYPES-integraatiotyökalu voi liittää muita väliohjelmistoprotokollia. (Features and Architecture, 2021.)
<p>&nbsp;</p> 

### OpenCV

OpenCV (Open Source Computer Vision Library) on avoimen lähdekoodin koneoppimisen ja -näön ohjelmistokirjasto. Se kehitettiin tarjoamaan yhteinen infrastruktuuri konenäön sovelluksille, jotta kaupallisten tuotteiden koneellinen tunnistus nopeutuisi.  OpenCV on BSD-lisensioitu (Berkeley Software Distribution) tuote mikä merkitsee sitä, että yritysten on helppo käyttää ja muokata koodia. Kirjastossa on yli 2 500 optimoitua algoritmia. Algoritmeja voidaan käyttää kasvojen sekä esineiden havaitsemiseen ja tunnistamiseen. Niillä voidaan luokitella mm. ihmisten erilaisia toimia, seurata liikkuvaa kohdetta, erotella 3D-mallit kohteista, yhdistää kuvia korkean resoluution aikaansaamiseksi, tunnistaa maisemat ja luoda merkkejä, joiden avulla maisema peitetään lisätyllä todellisuudella (engl. Augmented Reality, AR). Monet yritykset, tutkimusryhmät ja valtiolliset elimet käyttävät kirjastoa. ROS käyttää omaa sensor_msgs/Image viestimuotoaan. CvBridge on ROS-kirjasto, joka tarjoaa käyttöliittymän ROS:in ja OpenCV:n välillä. (About - OpenCV, 2021; cv_bridge/ Tutorials/ Using..., 2017.)

OpenCV:tä käytetään monenlaisissa eri sovelluksissa, joita ovat mm. katunäkymien kuvien yhdistäminen, automaattinen tarkistus ja valvonta, autonomisen auton navigointi ja hallinta sekä lääketieteellinen kuva-analyysi (OpenCV, 2021).
<p>&nbsp;</p> 

### Docker

Docker on sekä yritys että ilmainen ohjelmisto avoimen lähdekoodin yhteisölle.  Dockerissa voi luoda eristettyjä ympäristöjä projekteille ja asentaa riippuvuuksia, jotka eivät toisissa ympäristöissä aiheuta ongelmia muiden projektien kanssa. Näitä ympäristöjä kutsutaan konteiksi, jotka toimivat kuin virtuaalikoneet vaikka eivät sellaisia olekaan. Kontit eivät tarvitse erillistä käyttöjärjestelmää, vaan ne toimivat itsenäisesti laitteistokerroksen päällä jakaen isäntälaitteen resurssit. Muistia tarvitaan vähemmän ja nopeuttakin saattaa olla enemmän kuin virtuaalikoneella. Dockerin ja virtuaalikoneen eroavaisuus näkyy kuvassa kuusi. (Lentin & Ramkumar , 2019.)
  
![docker](/assets/images/Docker.png)
##### Kuva 6: Virtuaalikoneen ja Dockerin eroavaisuuksia (Lentin & Ramkumar, 2019)
 
 ROS-projekti saattaa koostua useista alapaketteja sisältävistä metapaketeista, joiden toimivuuteen tarvitaan riippuvuuksia. Voi olla ärsyttävää asentaa paketteja ROS:iin, sillä eri paketit saattavat käyttää joko samoja tai eri riippuvuuksia eri versioista johtaen näin kääntämisongelmiin. Kontit ovat käytännöllinen tapa ratkaista riippuvuusversiomuutosten vuoksi ilmaantuneita ongelmia. Ne ovat nopeita ja toisin kuin käyttöjärjestelmän prosessi voivat käynnistyä tai pysähtyä muutamassa sekunnissa. Laitteiston päivitykset tai paketit eivät vaikuta sisällä oleviin kontteihin tai muihin paikallaan oleviin kontteihin. (Lentin & Ramkumar , 2019.)

<p>&nbsp;</p>  
### Matlab & Simulink

Matlabilla on tehokas tietojenkäsittelykyky ja graafinen ohjelmointi, jolla voidaan käyttää suurta määrää kehittyneitä algoritmeja. Se on varustettu tehokkailla työkaluilla, kuten konenäkö, ohjausjärjestelmä sekä signaalinkäsittely. Näin ollen se on varsin hyödyllinen käyttöliittymä tutkijoille ja opiskelijoille. Matlab ja Simulink voidaan yhdistää ROS 1 ja ROS 2 verkkoon käyttämällä ROS Toolbox käyttöliittymää, jolloin voidaan vuorovaikutteisesti tutkia robotin ominaisuuksia ja visualisoida anturitietoja. ROS-yhteensopivilla roboteilla ja robottisimulaattorilla (esim. Gazebo) voidaan testata, kehittää ja tarkastaa robotiikan algoritmeja. Matlabilla ja Simulinkilla voidaan myös luoda itsenäinen ROS-verkko ja tuoda ROS-lokitiedostoja (rosbags) jolloin dataa voidaan visualisoida, analysoida tai jälkikäsitellä (Kuva 7). (Mahtani, et al., 2018; MathWorks, 2021.) 

![matlab](/assets/images/Matlab.png)
##### Kuva 7: ROS MATLAB ja Simulink tuki (MathWorks, n.d.) 

Jotta kommunikointi muiden solmujen kanssa onnistuu, voidaan Matlabissa ja Simulinkissa määrittää omat mukautetut viesti- ja palvelutyypit. Muiden Matlab-käyttäjien kanssa voidaan jakaa mukautettuja viestirajapintoja. Simulink Coder-sovelluksella voidaan luoda C++ koodi erilliselle ROS-sovellukselle, joka toimii millä tahansa Linux-alustalla. (MathWorks, 2021.)

<p>&nbsp;</p>  
### Tekoäly

Vuoteen 2000 saakka ihmisen tieto tallennettiin analogisiin laiteisiin, kuten kirjoihin, sanomalehtiin ja magneettinauhoihin. Vuonna 1993 tiedon pakkaamiseen olisi tarvittu 15,8 eksatavua tilaa eli 15,8 miljardia gigatavua. Vuonna 2018 tiedon määrä oli kasvanut 33 zetatavuun, joka taas on 33 000 miljardia gigatavua. Suurten tietomäärien lataamiseksi pilvipalveluntarjoajien on turvauduttava kuljettamaan kontinkokoisia kiintolevyjä. Kaiken tämän tiedon analysoimiseen tarvitaan myös laskentatehoa. Tietomäärän ja laskentatehon yhdistymisen myötä vuoden 2010 aikoihin tuli sekä mahdolliseksi että tarpeelliseksi opettaa koneita oppimaan. Yhdistämällä tekoäly robotiikkaan saadaan luotua älykkäämpiä autonomisia järjestelmiä. (Winder, 2021.)

Suuren yleisön suhtautuminen tekoälyyn ja yleiseen robotisaation kehitykseen on edelleen epäröivä ja ahdistunut, sillä luullaan niiden vievän työpaikat. Tosiasiahan on, että osa perinteisistä työpaikoista häviää ja osa muuttuu, mutta sen myötä syntyy myös uusia työpaikkoja. Tähän haasteeseen on vastattava opetuksen ja koulutuksen avulla. Taulukosta kahdeksan nähdään tekoälyn käyttötapauksia vuonna 2020. Tekoälytaitoja Euroopassa on kehitettävä ja edistettävä erilaisilla koulutusohjelmilla. Digitaalisia taitoja, tieteen, teknologian, tekniikan ja matematiikan taitoja, yrittäjyyttä ja luovuutta olisi tuettava. Yhteiskunnilla on edessään valtava muutos ja tekoälyn myönteisistä vaikutuksista olisi saatava tietoa kansan keskuuteen.  (Artificial Intelligence for..., 2020.)

![AI-kaytto](/assets/images/Kayttotapaukset.png)
##### Taulukko 3: Tekoälyn johtavat käyttötapaukset vuonna 2020. (Mehta & Senn-Kalb , 2021)

Sana tekoäly (engl. Artificial Intelligence, AI) aiheuttaa suurimmalle osalle ihmisistä paljon hämmennystä, josta suurin osa juontuu termien tekoäly ja koneoppiminen (engl. Machine Learning, ML) väärinkäytöstä. Lyhyesti ilmaistuna, tekoäly on tieteen ala, joka kattaa tietokoneiden kyvyn tehdä päätöksiä ja oppia kuten ihminen. Koneoppimisessa taas luodaan ohjelmisto, joka oppii sille annetusta datasta. Koneoppimistyyppejä ovat: valvottu oppiminen (engl. Supervised Learning), valvomaton oppiminen (engl. Unsupervised Learning) sekä vahvistusoppiminen (engl. Reinforcement Learning) (Kuva 8). (Olson, 2018.)

![AI](/assets/images/AI-kaavio.png)
##### Kuva 8: Kaaviossa nähdään intuitiivinen kuva tekoälyn kentästä (Palanisamy, 2018) 
 
Terminologia on hämmentävä, koska niihin liittyy sekoitus eri tekniikoita ja monessa on mukana sana ”oppiminen”. Esimerkkinä kolme koneoppimisen ydintyyppiä: Reinforcement Learning (RL), Deep Reinforcement Learning (DRL) sekä Deep Learning (DL). (Olson, 2018.)

*Reinforcement Learning*, vahvistusoppimisessa ei ole tarpeen tietää jokaista oikeaa askelta, riittää kun päämäärä on selvillä. Päätöksentekijä oppii kokeilemalla ja erehtymällä, vuorovaikutuksesta ympäristön kanssa. Ts. sen on itse opittava yrityksen ja erehdyksen kautta. Tekoäly saa joko palkkioita tai rangaistuksia suorittamistaan toimista samaan tapaan kuin esim. koiraa palkitaan herkuilla onnistuneesta suoritteesta. Ihmisen tehtävät rajoittuvat lähinnä ympäristön muuttamiseen ja palkitsemis- ja rangaistusjärjestelmän säätämiseen. Vahvistusoppiminen on tällä hetkellä tehokkain tapa ymmärtää koneen luovuutta. (Brown & Zai, 2020; Osiński & Budek, 2018; Winder, 2021.)

Robotiikan alalla on monia erilaisia sovelluksia, jotka käyttävät vahvistusoppimista. Näistä esimerkkejä ovat mm. robotin liikkeiden, teollisen valmistuksen parantaminen ja pannukakkujen kääntäminen. RL:n avulla voidaan parantaa pilvipalveluita, vähentää rakennusten käyttämän energian määrää, parantaa liikennevalojen hallintaa ja aktiivista kaistanhallintaa. Myös rahoitusala käyttää RL:ää kauppojen tekemiseen ja sijoitussalkkujen kohdentamiseen. Autonomiset ajoneuvot ovat myös hyvin aktiivisen tutkimuksen kohteena ja viime aikoina terveydenhuollossa on esiintynyt kiinnostusta vahvistusoppimiseen. Mikään ala ei siis jää koskemattomaksi. (Osiński & Budek, 2018.)

*Deep Learning*, syväoppiminen on suunniteltu kehittyneempien tehtävien suorittamiseen ja se koostuu useiden neuroverkkojen (engl. Neural Network, NN) kerroksista. Syväoppimisen malli on lähtöisin yksinkertaistetuista ihmisen aivoista. Nämä mallit koostuvat muutamista neuroverkoista, jotka periaatteessa oppivat tietystä datasta abstrakteja toimintoja asteittain. Jokainen neuroverkon kerros käyttää edellisen kerroksen tulosta syötteenä ja siten koko verkko koulutetaan yhtenä kokonaisuutena. Kehysympäristöt kuten Tensorflow, Keras ja PyTorch ovat tehneet koneoppismallien kehittämisestä paljon helpompaa. Hienoudestaan huolimatta syväoppimisen ratkaisut eivät vastaa ihmisen aivoja. (Osiński & Budek, 2018.)

Syviä neuroverkkoja on eri muotoisia ja kokoisia. Kaikki ne kuitenkin pohjimmiltaan perustuvat neuronien pinoamiseen. Sanalla ”syvä” viitataan suureen määrään piilotettuja kerroksia, joita tarvitaan abstraktien käsitteiden mallintamiseen. (Winder, 2021.)<br>
-	*Multilayer perceprions (MLPs)*, ovat syvistä neuroverkoista yksinkertaisimpia ja perinteisimpiä arkkitehtuureja. Täysin kytkettyjen NN-kerroksien ylimmän kerroksen neuronin tuotos ohjataan jokaisen alla olevan kerroksen neuroniin. Neuronien määrä syöttökerroksessa on sama kuin datan koko. Todennäköisyysjakauma luokkien välillä saadaan usein johtamalla neuronit softmax-funktion (monen luokan logistinen regressio) läpi. (Winder, 2021; Wood, n.d.)<br>
-	*Deep belief networks (DBNs)*, ovat kuin MLP:t, paitsi, että ylimmän kerroksen väliset tiedot voivat siirtyä takaisin toiselta kerrokselta ensimmäiselle. Ne ovat siis suuntaamattomia. Suuntaamattomat kerrokset ovat rajoitettuja Boltzmann-koneita (engl. Restricted Boltzmann Machines, RBMs). RBM sallii tiedon mallintamisen ja MLP kerrokset mahdollistavat luokittelun mallin mukaan. (Winder, 2021.)<br>
-	*Autoencoder* arkkitehtuuri kaventuu keskikohtaa kohti kuten tiimalasi ja sen tavoitteena on tuottaa syötedataa mahdollisimman hyvin ottaen huomioon kavennuksen rajoitteet, ollen näin eräänlainen puristusmuotti. Monissa arkkitehtuureissa ”autoenkoodaajat” ovat eräänlaisia autonomisia ominaisuuksien poimijoita. (Winder, 2021.)<br>
-	*Convolutional Neural Networks (CNNs)*, toimivat hyvin alueilla, joilla yksittäiset havainnot korreloituvat paikallisesti. Oletuksena CNN esiprosessoi datan konvoluutioksi kutsuttujen suodattimien avulla. Monien suodatinkerrosten jälkeen tulos syötetään MLP:hen. (Winder, 2021.)<br>
-	*Recurrent NNs*, ovat arkkitehtuuriluokka, joka palauttaa yhden aika-askeleen seuraavaan syötteeseen. RNN:t ”muistavat” menneisyyden ja voivat siten hyödyntää tietoja päätösten tekemisessä. Takaisinkytkennästä johtuen ovat RNN:t pahamaineisen tunnettuja vaikeasti koulutettavina. Pitkä lyhytkestomuisti (engl. Long short-term memory, LSTM) ja porteilla rajatut toistuvuusyksiköt (engl. Gated Recurrent Units, GRUs) parantavat RNN-arvoja katkaisten tuhoisan takaisinkytkennän. (Winder, 2021.)<br>
-	*Echo state networks (ESNs)*, käyttävät satunnaisesti alustettua RNN-varantoa muuntaakseen tulot suurempiin dimensioihin. ESN avulla RNN:ia ei tarvitse kouluttaa, jolloin siihen liittyvät ongelmat poistuvat. (Winder, 2021.)

*Deep Reinforcement Learning*, syvävahvistusoppiminen yhdistää kahden edellä mainitun parhaat puolet.  NN on vastuussa kokemusten tallentamisesta ja siten parantaa tehtävän suorittamista. Tyypillisesti DRL:ssä ympäristö on kuvattu kuvilla. Kuvat analysoidaan ja niistä poimitaan asiaankuuluvat tiedot. Saatuja tietoja käytetään informoimaan mitä toimintoja tulisi suorittaa. Syvävahvistusoppiminen suoritetaan yleensä joko arvopohjaisena tai käytäntöperusteisena oppimisena. DRL:n ja DL:n ero on siinä, että ensimmäisessä syötteet muuttuvat jatkuvasti, kun taas jälkimmäisessä näin ei ole.  (Nelson, 2021.)

Arvopohjaiset oppimistekniikat käyttävät algoritmeja ja arkkitehtuureja kuten konvoluutio neuroverkkoja ja Deep-Q-Networksia. Algoritmi muuntaa kuvan harmaasävyiseksi ja rajaa kuvasta tarpeettomat osat. Kuvan olennaisimmat osat käyvät läpi erilaisia konvoluutio- ja yhdistämisoperaatioita. Tärkeistä osista lasketaan Q-arvo eri toiminnoille, jotka voidaan suorittaa. (Nelson, 2021.)

Käytäntöperusteisia menetelmiä käytetään, kun on mahdollista toimia erittäin monella eri tavalla. Q-arvojen laskeminen jokaiselle yksittäiselle toimelle ei ole käytännöllistä, siksi tarvitaan erilainen lähestymistapa. Yksittäisen arvon laskemisen sijaan käytännöt opitaan usein suoraan ”Policy Gradient”-tekniikoilla. Nämä tekniikat vastaanottavat tilan ja laskevat toiminnan todennäköisyydet aiempien kokemusten perusteella. Todennäköisin toiminta valitaan. Tätä toistetaan arviointijakson loppuun saakka, jolloin palkinnot jaetaan ja verkon parametrit päivitetään vastavirta-algoritmilla. (Nelson, 2021.)

![AI](/assets/images/deepsense.png)
##### Kuva 9: Suunnikkaan – suorakulmion – neliön suhde (Osiński & Budek, 2018)

Kuvasta 9 nähdään, ettei näiden koneoppimisten välissä ole itseasiassa mitään selvää eroa. Laajin luokka on ML ja kapein puolestaan DRL. RL puolestaan on kone- ja syväopetustekniikoiden erikoissovellus, joka on suunniteltu ratkaisemaan ongelmia tietyllä tapaa. Erilaisissa projekteissa malleja ei ole suunniteltu pitämään kiinni vain yhdestä tietystä tyypistä vaan suorittamaan annettu tehtävä mahdollisimman tehokkaasti. Mitkään näistä eivät kuitenkaan korvaa toisiaan.  (Osiński & Budek, 2018.)<br>
Vuosien saatossa tekoäly on kehittynyt reaktiivisuudesta tietoisuuteen (Kuva 12). Tekoälyn soveltaminen edistää kasvua yksilö-, yritys- ja taloustasolla. Se tukee ja nopeuttaa tuottavuuden kasvua mikro- ja makrotasolla. (Mehta & Senn-Kalb , 2021.)

![Evolution](/assets/images/assets.png)
##### Kuva 10: Tekoälyn kehityskulku (Mehta & Senn-Kalb , 2021)

Mikrotasolla hyötyjä odotetaan olevan mm. alentuneet työvoimakustannukset, lisääntynyt suorituskyky, parempi laatu ja lyhyemmät seisonta-ajat. Makrotasolla taas puolestaan automaation odotetaan johtavan tuottavuuden kasvuun (Taulukko 4).

![Tuottavuus](/assets/images/tuottavuus.png)
##### Taulukko 4: Tekoälyn vaikutus työn tuottavuuteen kehittyneissä maissa vuonna 2035. (Mehta & Senn-Kalb , 2021)

Hyödyistään huolimatta koneet ovat improvisoinnin suhteen edelleen rajallisia. Ne seuraavat enimmäkseen valmiiksi ohjelmoituja algoritmeja, jotka sallivat niiden toimia vain ennalta määrätyillä tavoilla. Uuden tilanteen edessä ja ”terveen järjen” puuttuessa ne ovat mahdottoman edessä. Koneet alkavat kuitenkin pikkuhiljaa voittaa ihmiset eri aloilla, jopa niillä, jotka vaativat kognitiivisia kykyjä. (Mehta & Senn-Kalb , 2021.)

Alla muutama esimerkki:
-	Libratus: Carnegie Mellonin yliopiston kehittämä tekoäly. Ensimmäinen tietokone, joka voitti neljä pokerin ammattilaista.
-	AlphaGo: Googlen DeepMindin kehittämä tekoälyjärjestelmä, joka voitti maailman parhaana Go-pelin pelaajana pidetyn Lee Sedolin. Go on muinainen kiinalainen lautapeli, jossa on lukemattomia permutaatioita ja yhdistelmiä.
-	Tekoälykone nimeltä Dr. Fill voitti toukokuussa 2021 lähes 1 300 ihmistä amerikkalaisessa ristisanatehtäväturnauksessa.

(Mehta & Senn-Kalb , 2021.)
<p>&nbsp;</p>  

### OpenAI

OpenAI on San Franciscon lahden alueella sijaitseva tekoälyn tutkimuslaitos ja yksi heidän suurimmista panoksistaan on avoimen lähdekoodin OpenAI ”Gym”. Pythonille julkaistu paketti tarjoaa monia ympäristöjä, joissa käyttäjät voivat aloittaa vahvistavien oppimisalgoritmien käytön. Työkalupakki esittelee standardin ohjelmointirajapinnan liitännän RL oppimiseen suunnattujen ympäristöjen kanssa. Jokaisessa ympäristössä on versio, joka takaa tähdelliset vertailut ja toistettavat tulokset kehittyvien algoritmien ja ympäristön kanssa. RL:n yhteydessä ympäristöllä viitataan varsinaiseen tehtävään, Markovin päätöksentekoprosessiin (engl. Markov Decision Process, MDP), joka ratkaistaan algoritmin avulla. Ympäristö määrittää tehtävän tilan ja toimintavälin. (Beysolow II, 2019; Habib, 2019; Palanisamy, 2018.)
<p>&nbsp;</p>  

### ROS Industrial

Vuonna 2012 Yaskawa Motoman Robotics, Willow Garage ja saksalainen Southwest Research Institute (SwRI) aloittivat ROS-Industrial projektin. ROS-Industrial laajentaa ROS-ohjelmiston kehittyneitä ominaisuuksia teollisuusrobotteihin. Se koostuu monista ohjelmistopaketeista, joita voidaan käyttää teollisuusrobottien rajapinnassa. Paketit ovat BSD/Apache 2.0 lisensioituja ja ne pitävät sisällään kirjastoja, ohjaimia ja työkaluja teollisuuslaitteille. (Mahtani, et al., 2018.)<br>
ROS-Industrial mahdollistaa laitteiden käytön langattomissa verkoissa, edistyneen 2D-näön sekä 3D-pistepilvisensorien käsittelyn. Ohjelmiston kehitystyökaluihin kuuluu yleinen tiedonkeruu, virheiden tarkastus sekä automatisoitu koodaus. Monien robotin reitin suunnittelijoiden ja optimoijien avulla kehittäjät voivat valita ja mukauttaa korkean tason vapausasteen omaavia järjestelmiä. (Southwest Research Institute..., 2012.)<br>
ROS-Industrial konsortio käyttää laajasti MoveItia jo olemassa olevien kaupallisten robottien hallintaan, kuten Kuka, Universal Robots, Motoman, ABB sekä Fanuc. ROS-Industrial paketit tarjoavat sekä yhteyden MoveItiin että robottien ROS-ohjaimet, joiden avulla hallita robotteja. (Tellez, 2018.)
<p>&nbsp;</p>  

### MoveIt

MoveIt on avoimen lähdekoodin projekti, joka on saatu aikaan suuren kansainvälisen yhteisön ja useiden organisaatioiden yhteistyöllä. Se on joukko työkaluja, jotka on tarkoitettu mobiilikäyttöön. Internet-sivusto sisältää dokumentaatiota, opetus- ja asennusohjelmia sekä esimerkkiesittelyjä monilla käsivarsiroboteilla tai roboteilla, jotka käyttävät MoveItia manipulointiin. Kirjasto sisältää nopean käänteisen kinematiikan ratkaisijan, huipputason algoritmeja manipulointiin, 3D-havainnollistuksen, kinematiikan, kontrolloinnin sekä navigoinnin. Lisäksi se tarjoaa helppokäyttöisen käyttöliittymän uusien käsivarsirobottien määrittämiseen ja Rviz-liitännät liikkeiden suunnitteluun. Sitä on käytetty yli 150 eri robottiin. (Martinez, et al., 2018; Moving robots into..., n.d.)

![moveit](/assets/images/MoveIt.png)
##### Kuva 11: MoveIt! arkkitehtuuri (Martinez, et al., 2018)

Move_group-elementin ajatuksena on, että liitäntäryhmät ja muut elementit määritellään liikkeensuunnittelualgoritmien avulla (Kuva 11), jotta liiketoiminnot saadaan suoritettua. Nämä algoritmit käsittelevät paikan ja ryhmän liitäntöjen ominaisuudet, joissa kohteet ovat vuorovaikutuksessa. Ryhmä määritetään käyttäen ROS:in vakio työkaluja ja määrityskieliä kuten YAML (YAML Ain’t Markup Language), URDF ja SDF (Simple Data Format). Ryhmään kuuluvat nivelet on siis määriteltävä niiden liitäntärajoilla. MoveIt tarjoaa GUI-toiminnon (Graphical User Interface), jolla määrittely tietylle robotille voidaan tehdä. Määrittelyn jälkeen voidaan suorittaa liittyminen C++ ja Python rajapinnan avulla. MoveIt sallii erilaisten kirjastojen käytön liikkeen suunnitteluun, kuten OMPL (Open Motion Planning Library), käyttäen ROS-toimintoja tai -palveluita. (Martinez, et al., 2018.)

Yksi MoveItin tärkeimmistä ominaisuuksista on törmäyksien ja niiden välttämisen tarkistus. Tämä tehdään rinnakkain liikesuunnittelun ja IK-algoritmi (Inverse Kinematics) ratkaisun kanssa. Robotti voi törmätä joko itsensä (mallista riippuen) tai jonkin ympäristössä olevan kanssa. MoveIt kykenee hallitsemaan molemmat tapaukset. Pakettiin on sisällytetty avoimen lähdekoodin FCL (Flexible Collision Library), joka suorittaa erilaiset törmäyksen havainnointi- ja välttämisalgoritmit. Törmäyksen tarkistukseen kuuluu objekteja kuten mesh-verkko, primitiiviset muodot, kuten laatikot ja sylinterit sekä OctoMap. (Martinez, et al., 2018.)

OctoMap-kirjasto muodostaa 3D-varauksellisen ruudukon, jota kutsutaan ”octreeksi”. Se koostuu ympäristön esteiden tilastomatemaattisesta tiedosta. MoveIt-paketti rakentaa OctoMapin käyttämällä 3D-pistepilveä ja siirtämällä se suoraan FCL:lle törmäyksen tarkistusta varten. (Martinez, et al., 2018.)
<p>&nbsp;</p> 

### SROS

Kehitteillä oleva ja kokeellinen SROS (Secure ROS) tukee alkuperäistä TLS-toimintoa (Transport Layer Security) tarjoten näin ROS-ohjelmointirajapintaan ja ekosysteemiin lisäystä, jolla tuetaan nykyaikaisia salauksia ja turvatoimia. Ominaisuuksiin kuuluvat mm. natiivi TLS-tuki kaikille IP/liitäntä tason viestinnälle, luottamusketjujen salliminen x.509-sertifikaattien avulla, määriteltävissä oleva nimitila ROS-solmujen rajoituksille ja sallituille rooleille sekä kätevä käyttäjätilan työkalu solmujen avainparien automaattiseen luomiseen sekä ROS-verkkojen tarkistus, pääsynvalvonnan rakentaminen ja kouluttaminen. (Portugal, et al., 2018; White, et al., 2016.)

TLS:n käyttö kahden kommunikoivan sovelluksen välillä edesauttaa yksityisyyttä, henkilöllisyyden todennusta sekä datan eheyttä. Käynnistyksen yhteydessä SROS tarjoaa ROS-riippumattoman avainpalvelimen, joka luo ja jakaa avaimia ja sertifikaatteja ROS-solmuille. Saumattomasti integroitu SROS:in avainpalvelin yksinkertaistaa käyttäjien kokemuksia ja kehitystä. (Portugal, et al., 2018.)
<p>&nbsp;</p>  

### Rosbridge

Rosbridge tarjoaa robotiikkaan ylimääräisen sovelluskerroksen (Kuva 12), joka mahdollistaa muidenkin kuin ROS-asiakasprosessien toiminnan yhdessä ROS-prosessien kanssa, mukaan lukien Web-rajapinnat. Rosbridge suhtautuu ROS:iin palvelinpuolena. Näin sovelluskehittäjät eivät tarvitse intiimejä tietoja matalan tason ohjausrajapinnoista, väliohjelmien koontijärjestelmistä tai monimutkaisista robotintunnistus- ja ohjausalgoritmeista. Minimissään heidän on kuitenkin ymmärrettävä väliohjelmistopaketin rakenne ja kuljetusmekanismit. (Crick, et al., 2016.)

![rosbridge](assets/images/Rosbridge.png)
##### Kuva 12: Rodbridgea käyttävän verkkosovelluksen rakenne (Alexander & al., 2012) 

Rosbridgen avulla asiakkaat voivat julkaista ja tilata ROS-aiheita ja käynnistää ROS-palveluita palvelimen ajonaikaisessa ympäristössä kuljettamalla JSON-muotoiset (JavaScript Object Notation) viestit TCP- ja Websockettien kautta. Rosbridgen asiakkaat ovat kieliriippumattomia, tarkoittaen sitä, että voidaan käyttää mitä tahansa Websocketin tukemaa kieltä. Se ei myöskään rajoita asiakkaita ROS:iin. Rosbridge mahdollistaa yksinkertaisen viestinkäsittelyn sekä HTML5-verkkosovitteissa (Hypertext Markup Language) että standardeissa POSIX IP (Portable Operating System Interface) suoritinkannoissa. Esimerkkinä ”/sensorPacket” niminen ROS-aihe, jonka julkaisijana on yksinkertainen Python-asiakas (Kuva 13). (Alexander, et al., 2012; Crick, et al., 2016.)

![rosbridge](assets/images/sensorPacket.png)
##### Kuva 13: "sensorPacket", ROS-topic (Crick & al., 2016)

JSON-pohjainen rosbridge protokolla on suunniteltu mahdollistamaan datan julkaisu, tilaaminen ja palveluiden hyödyntäminen minkä tahansa asiakkaan ja palvelimen välillä alustasta riippumatta. Onnistuneita toteutuksia on tehty mm. Linuxilla, Windowsilla, iOS:lla, Androidilla ja yleisillä Web-selaimilla. Vakaa ROS rosbridge-palvelin ja protokolla löytyvät ROS.org sivuilta: http://wiki.ros.org/rosbridge_suite (Alexander, et al., 2012.)  
<p>&nbsp;</p> 

### ROSJS

Vuosien varrella laskentaparadigmat ovat kehittyneet ja nykyinen tekniikka mahdollistaa avoimen hallinnon, ylimääräisen muistin ja välittömän heterogeenisillä alustoilla toimivien ohjelmistojen käyttöönoton älypuhelimista moniytimisiin pöytäkoneisiin. Tämä on synnyttänyt joukon käyttäjiä, jotka ymmärtävät perusverkkoteknologiat, kuten HTML ja JavaScript. Osaaminen ulottuu ammattimaisten sovelluskehittäjien ulkopuolelle, käyttäjiin, jotka eivät ehkä kutsu itseään ohjelmoijiksi, mutta kuitenkin käyttävät verkkoa kaikkeen luovaan. Rosbridgen tavoitteena onkin laajentaa robotiikkaa kirjailijoiden, artistien, opiskelijoiden ja suunnittelijoiden joukkoon. JavaScriptistä on tullut verkon oletuskieli ja se onkin yksi maailman suosituimmista kielistä. (Crick, et al., 2016.)

JavaScript kirjasto nimeltään ros.js rakennettiin helpottamaan viestintää selaimen ja rosbridgen välillä. Käyttäen ros.js ja rosbridgea selaimessa käynnissä oleva JavaScript sovellus kykenee kommunikoimaan etärobotilla tai palvelimella olevan ROS-sovelluksen kanssa. Ros.js on suunniteltu kevyeksi ja tapahtumapohjaiseksi. Sen kevyt koodi sallii helpomman integraation jo olemassa oleviin, laajamittaisiin JavaScript sovelluksiin. Tapahtumapohjainen ros.js mahdollistaa responsiivisemman käyttöliittymän ja erottaa ros.js moduulin muista JavaScript-moduuleista. (Alexander, et al., 2012.)  
<p>&nbsp;</p>  

# Turvallisuus verkossa

Robottien laaja lisääntyminen useilla eri aloilla on herättänyt keskustelua niiden käytön turvallisuudesta. Turvallisuus onkin ollut usein unohdettu ongelma robottijärjestelmissä, sillä painopiste on yleisesti ollut vain niiden toiminnallisuudessa ja innovaatioissa. Vaikka robottien käytön hyödyt on laajalti tiedostettu ja dokumentoitu, aiheuttavat nämä uusia turvallisuus- ja yksityisyydensuoja ongelmia. Aikaisemmin teollisuusrobotteja käytettiin pääsääntöisesti vain tehdasympäristöissä, joissa niiden suojana oli seinät ja suljettu verkko. Järjestelmien kehittyessä robotit siirtyvät pois suljetuista ympäristöistä. Yhdistettynä internettiin ja rakennettuna perinteisille tietokonealustoille ne ovat alttiina kyberhyökkäyksille sekä kokonaan uudelle joukolle turvallisuusriskejä, jotka voivat hakkeroinnin kohteeksi joutuessaan aiheuttaa tietoturvaongelmia tai jopa fyysisiä vahinkoja. (DiLuoffo, et al., 2018; Portugal, et al., 2018.) 

Oletusarvoisesti tietoturvasuojaus ei kuulu ROS 1:seen. Tämä altistaa robotit haitallisille hyökkäyksille. Luvaton kuuntelija voi helposti siepata ja tulkita viestiä, kerätä tietoja ja väärentää tietoja järjestelmään, sillä ROS 1 käyttää solmujen väliseen kommunikaatioon selkotekstiä (clear text) TCP/IP:n (Internet Protocol) ja UDP/IP:n kautta. ROS 1 tarkistaa vain viestin sanarakenteen MD5 (Message Digest algorithm 5) summasta ovatko osapuolten väliset asettelut samanlaisia. ROS 1:sen modulaarisuus aiheuttaa joitakin haittoja, kuten TCP-porttien altistumisen, nämä kun eivät vaadi mitään todennusta. Varmistamattomien ja suojaamattomien TCP-porttien käyttö sekä todennusmekanismin puute voivat johtaa pahansuopiin puhujiin, jotka sotkevat järjestelmän. (Brookes, 2011; Portugal, et al., 2018.)

ROS 1 käyttää myös anonyymia julkaisu/tilaussemantiikkaa. Solmut eivät täten ole tietoisia kenen kanssa ne ovat yhteydessä. Järjestelmä käyttää heikkoa auktorisointirakennetta, joilla ei ole lähettäjän, tietojen rehellisyyden tai aitouden varmistusta eikä käyttöoikeuksien tason määritystä. Kommunikoidakseen ROS 1 tarvitsee kaksisuuntaisen verkon kaikkien tietokoneiden välillä. Tällöin solmujen palomuurien asetuksien pitää olla vähemmän tiukkoja aiheuttaen ylimääräisen turvallisuusriskin ja ylimääräisen verkon resurssien käytön, kuten esim. kaistanleveys, energia, muisti tai aika. Jokainen solmu vastaa omasta kommunikaatioistaan, viestejä ei tiivistetä eikä verkkokommunikaatiota vähennetä. (Portugal, et al., 2018; What is Network..., 2021).

Käynnistettäessä ROS-isäntä aukeavat portit mille tahansa verkkokoneelle. Nämä koneet voivat kysellä ROS-isännältä kriittisiä tehtäviä kuten ROS TCP/UDP yhteyksien asettamista muiden solmujen kanssa, minkä tahansa aiheen tilaamista, verkon solmun lopettamista jne. Samassa verkossa oleva pahansuopa entiteetti voi päästä hyväksikäyttämään kaikkea robotin dataa kuten esim. lähettää komentoja, tukkia verkkoyhteyksiä, käyttää kameraa yms. (Portugal, et al., 2018.)

Ilman lisätoimia järjestelmän käytön rajoittamiseksi ROS.org sivuilla suositellaankin, ettei ROS-isäntää pidä koskaan yhdistää julkiseen Internettiin tai verkkoon, johon on pääsy käyttäjillä, joilla ei ole siihen lupaa.  Sivuilla suositellaan kahta erilaista tapaa, joilla rajoittaa pääsyä ROS-isäntä solmuun: verkon käyttämisen rajoittaminen kuten eristetyn verkon luominen tai palomuurin käyttö sekä erilaiset ROS laajennukset, jotka voivat todentaa käyttäjät ennen komentojen sallimista. (Security, 2020.)

### Verkon käyttö suojauksessa

Suositeltavinta on käyttää ROS:sia verkossa, joka ei ole yhdistetty Internettiin tai joka on verkossa palomuurilla määritetty estämään ROS-pääportista (TCP 11311) saapuva liikenne. Yleinen asetus on ajaa ROS-isännät erillisessä verkossa kuluttajareitittimen takana, joka suorittaa Network Address Translation (NAT) jotta useat laitteet voivat jakaa saman julkisen IP-osoitteen.  NAT estää saapuvat yhteydet, joita sisäiset isännät eivät ole käynnistäneet, jolloin NAT:in takana oleva isäntä ei ole oletusarvoisesti näkyvissä Internetissä. NAT ei kuitenkaan ole turvallisuuslaitteisto. Se voidaan määrittää väärin tai sillä voidaan avata portit ulkopuolista käyttöä varten. Käytettäessä eristettyä verkkoa tai NAT:ia, ulkopuolisille verkon käyttäjille voidaan antaa pääsy käyttäen VPN:ää (Virtual Private Network) tai jotain muuta vastaavaa ratkaisua. Käytettäessä ROS:ia kannettavalla tietokoneella tai jollain muulla mobiilijärjestelmällä olisi tärkeää tiedostaa mitä verkkoa ollaan käyttämässä, jottei vahingossa käy niin, että siirrytään eristetystä verkosta avoimeen, jolloin päälle jäänyt isäntä pääsee vaarantumaan. (Security, 2020.)

### Palomuurin määritys

Palomuurin määrittämiseksi on päätettävä mikä IP-osoitealue edustaa IP-osoitteita, joille sallitaan yhteyden muodostus. Tähän sisäiseen verkkoon voi halutessaan liittää yhden tai useampia IP-osoitteita. (Security, 2020.)

Palomuurin olisi kuitenkin suotavaa toimia seuraavasti:
-	*Sallia kaikki liikenne sisäisestä verkosta ROS-isäntäporttiin, jotta ROS-isäntä liikenne mahdollistuu*
-	*Sallia kaikki sisäisen verkon uudet TCP ja UDP yhteydet mistä tahansa portista tilaajia varten*
-	*Sallia liikenne muista porteista muita palveluita varten*
-	*Estää muista verkoista tulevia uusia TCP ja UDP yhteyksiä*

(Security, 2020.)


### Verkkoyhteyden luominen teollisuusroboteilla

Tyypillisesti teollisuusrobotit ovat yhdistettyinä tietokoneeseen, jossa on ROS asennettuna ja joka käyttää ns. liikepalvelinta (Kuva 14). Ohjelmat on kirjoitettu OEM kielellä (Original Equipment Manufacturer) jotka ovat käytössä teollisuusrobottien kontrollereissa ja mahdollistavat akseleiden paikkatietojen vastaanottamisen ja todellisten tietojen sekä tilan lähettämisen robottien ROS-ohjaimelle. OEM kielissä on eroja riippuen valmistajasta. Tällä hetkellä valmistajat eivät tarjoa käyttöliittymiä, jotka mahdollistavat salauksen tai oikeuksien todentamisen eikä toimenpidettä voida lisätä robotin kontrollerissa ajettuun liikepalvelinohjelmiin. Tämä mahdollistaa ROS-robottiohjaimeen ja siinä toimivaan liikepalvelinohjelmaan kohdistuvat hyökkäykset. (Security, 2020.)
![security](/assets/images/kytkenta.png)

##### Kuva 14: Teollisuusrobotin yleinen kytkentä ja mahdollinen hyökkäys (wiki.ros.org/Security, 2020)

Jotta minimoidaan riskit hyökkäyksille, on verkko määritettävä oikein. ROS-koneen ja robotin kontrollerin yhteys on oltava eristettynä muista verkoista. Tämä voidaan tehdä käyttämällä esimerkiksi kahta verkkoadapteria, jotka on yhdistetty kahteen eri verkkoon (Kuva 15). (Security, 2020.)

![security](/assets/images/verkko.png)
##### Kuva 15: Esimerkki verkon konfiguraatiosta (wiki.ros.org/Security) 

Toinen adapteri on yhdistettynä teollisuusrobotin kontrolleriin (Net2 adapteri) ja toinen yhdistettynä paikallisen verkon reitittimeen (Net1 adapteri). Nämä adapterit on määritettävä eri aliverkko-osoitteilla ja edelleenlähetystä pitäisi välttää. (Security, 2020.)

DDS:n lisääminen yksinään ei ole kokonaisvaltainen robotiikan suojausmalli sillä järjestelmän osat voivat ali- tai ylikuormittua. Seurauksena voi olla heikentynyt suorituskyky tai odottamattomia haavoittuvuuksia. Robottijärjestelmien yhteydessä DDS:n lisääminen aiheuttaa sekä turvallisuus- että mahdollisia suorituskykyhuolia, jotka johtuvat ROS:n pub – sub paradigman aiheuttamasta suuresta viestiliikenteestä sekä muista kompromisseista liittyen laitteisto- ja ohjelmistojärjestelmien elementteihin. (DiLuoffo, et al., 2018.)

Eräät tutkijat ovat jakaneet ROS 2:sen haavoittuvuudet kolmeen eri kategoriaan: invasiivinen, ei-invasiivinen sekä puoli-invasiivinen. Näiden haavoittuvuuksien yhteenveto ja suhde sovellettavaan kerrokseen on esitetty kuvassa 16. (Basheer & Varol, 2019.)

![security](/assets/images/haavoittuvuudet.png)
##### Kuva 16: ROS-tekniikkaa käyttävien robottien haavoittuvuudet (Basheer & al.,2019)

On tärkeä ymmärtää, että erilaisilla roboteilla kuten esim. herkkien esineiden manipulointiin tarkoitetuilla ja julkisilla teillä liikkuvilla autonomisilla ajoneuvoilla on erilaiset käyttöympäristöt ja siten hyvin erilaiset turvallisuusvaatimukset. Riippuen robottien tyypistä ja toiminnoista PKI-komponenteille (Public Key Infrastructure) ja yksittäisten vahvistuksien suorittamiselle tulisi asettaa suojauskäytäntö. ROS 2 mahdollistaa eri robottijärjestelmien suojaustekniikat joustavalla toimialueiden ja osallistujien segmentoinnilla. Robottijärjestelmän turvallisuuden määrittäminen voidaan ratkaista käyttämällä kaksitasoista pääsynvalvontaa eli hallinto- ja käyttöoikeuskäytäntöä. Välttämätöntä on kuitenkin suorittaa haavoittuvuusanalyysi, jotta riskit ja niiden vähentäminen voidaan määrittää. Kokonaiskuvasta nähdään, että ROS 2:ssa on parannettu turvallisuutta, mutta monet tasot ovat edelleen alttiina. (DiLuoffo, et al., 2018.)
<p>&nbsp;</p>  

# Ethernet

Ethernet kehitettiin Xeroxin Palo Alto-tutkimuskeskuksessa (Palo Alto Reseach Center, PARC) 1970-luvulla edulliseksi ja vikasietoiseksi verkkoliittymäksi sekä lähi- (engl. Local Area Network, LAN) että alueverkoille (engl. Wide Area Network, WAN). Ethernet julkaistiin virallisesti vuonna 1985. Sen nopeus oli 10 Mb/s, joka oli siihen aikaan erittäin nopea. Vuonna 1995 kehitettiin 100 Mb/s Fast Ethernet (FE), jonka verkkokortit (engl. Network Interface Controller, NIC) kykenevät automaattisesti säätämään nopeutta 10–100 Mb/s välillä. Gigabit Ethernet (GE) julkaistiin vuonna 1999, mutta sen käyttö yleistyi vasta vuoden 2010 paikkeilla. Sekä Fast Ethernetia, että Gigabit Ethernetia käytetään verkkoyhteyksissä. Ne voivat toimia kuitukytkimen, valokuitukaapelin, Ethernet kaapelin ja joidenkin vastaavien laitteiden kanssa. (Fast Ethernet vs..., 2018; Smith, 2020; Spurgeon & Zimmerman, 2014.)

![Ethernet](/assets/images/Ethernet.png)
##### Kuva 17: Ethernet kommunikointi kenttäväylän kautta. (What is Fieldbus?, n.d.)

Kenttäväylä on yksinkertainen tapa kommunikoida syöttö- ja tulostuslaitteiden kanssa ilman, että jokainen laite on kytkettävä takaisin ohjaimeen (Kuva 19) ts. se on digitaalinen kaksisuuntainen monipistekommunikaatioyhteys älykkäiden kenttälaitteiden välillä. Näitä kenttäväylävaihtoehtoja on useita erilaisia. Tämä johtuu siitä, että automaatiolaitteiden valmistajat ovat kehittäneet omia kenttäväyliään, joilla on erilaiset ominaisuudet ja toiminnot ja joilla kilpailla keskenään teknisellä tasolla. Laitteistorajapinnat ovat tärkeitä ROS:in integroinnissa tuotantojärjestelmiin. (Sen, 2014; What is Fieldbus?, n.d.)

### EthetCAT

Vuonna 2003 merkittävä teollisuusautomaation ja ohjelmoitavien logiikkaohjainten valmistaja Beckhoff Automation kehitti EtherCAT:n (Ethernet for Control Automation Technology). Heti seuraavana vuonna he lahjoittivat oikeudet ETG:lle (EtherCAT Technology Group) jotka ovat vastuussa standardin edistämisestä.  (Smith, 2020.)

EtherCAT on suurin ja nopein Ethernet-tekniikka, jonka synkronointi tapahtuu nanosekunnin tarkkuudella. Tästä hyötyvät sovellukset, joiden kohdejärjestelmää ohjataan tai mitataan väyläjärjestelmän kautta. Odotusaikojen vähentyminen parantaa sovelluksien tehokkuutta merkittävästi. EtherCAT:n järjestelmäarkkitehtuuri vähentää CPU:n (Central Processing Unit) kuormitusta jopa 25–30 % verrattuna muihin väyläjärjestelmiin. Näin ollen myös kustannukset alentuvat. Perinteisissä Etherneteissa verkon topologia on rajoittunutta, mutta EtherCAT:ssa ei tarvita keskittimiä eikä kytkimiä, jolloin se on käytännössä rajaton verkon topologian suhteen. Viiva-, puu-, tähtitopologiat ja erilaiset yhdistelmät ovat kaikki mahdollisia lähes rajattomalla määrällä solmuja (Kuva 18). (Why use EtherCAT?, n.d.)

![ethercat](/assets/images/ethercat.png)
##### Kuva 18: EtherCAT verkko rengastopologialla. (Smith, 2020)

EtherCAT voidaan asettaa määrittämään osoitteet automaattisesti. Sen pieni väyläkuorma ja vertaisfysiikka auttavat sietämään sähkömagneettisen kohinan aiheuttamia häiriötä. Verkon tunnistaessa mahdolliset häiriöt, vähenee vianetsintään käytettävä aika. EtherCAT:in suorituskyky poistaa tarpeen virittää verkkoa ja sen suuri kaistanleveys mahdollistaa TCP/IP:n ja ohjaustiedon lähettämisen samanaikaisesti. Functional Safety over EtherCAT:n (FSoE) ansiosta toiminnallinen turvallisuus integroituna osana verkkoarkkitehtuuria on todistetusti käytössä TÛV-sertifioiduilla (Technischer Überwachungsverein, engl. Technical Inspection Association) laitteilla. Protokolla sopii sekä keskitetyille että hajautetuille järjestelmille ja sitä voidaan käyttää myös muissa väyläjärjestelmissä. Toimiakseen EtherCAT:n päälaite vaatii vain Ethernet-portin, liitäntäkortit tai rinnakkaisprosessorit eivät ole tarpeen. Orjaohjaimia on saatavilla eri valmistajilta eri muodoissa: ASIC (Application Specific Integrated Circuit), FGPA (Field Programmable Gate Array), tai vaihtoehtona standardi mikroprosessorisarjoille. (Singh, 2018; TUV Rheinland Certificate, 2019; Why use EtherCAT?, n.d.)

### Modbus

Modbus protokolla kehitettiin vuonna 1979 Modicon (nyk. Schneider Electric) nimisen yhtiön toimesta. Sen tarkoitus oli jakaa tietoja heidän omien PLC:sä (Programmable Logic Controller) välillä. Se julkaistiin avoimena ja kuka tahansa voi käyttää sitä ilman oikeudellisia seuraamuksia. Tämän johdosta siitä tuli yleisesti hyväksytty ”de facto”-standardi, ja se on nyt yleisimmin saatavilla oleva keino yhdistää teollisuuden elektroniset laitteet. Vuodesta 2004 sen hallinta on ollut käyttäjien ja toimittajien yhteisöllä, joka tunnetaan nimellä Modbus-IDA. (Sousa & Portugal, 2011; What is Modbus..., n.d.)

Modbus on tietoliikenneprotokolla, jolla voidaan lähettää ja vastaanottaa tietoja sarjaliikenneväylien, kuten RS232 ja RS485 kautta. Vuonna 1999 julkaistu Modbus/TCP-spesifikaatio määrittää IP-pohjaisen linkkikerroksen Modbus-kehyksille. Modbus TCP/IP-protokollan käyttämisellä on useita etuja, kuten yksinkertaisuus, standardi Ethernetin käyttö sekä avoimuus. Modbus käyttää isäntä-orja-arkkitehtuuria, jossa yksi solmu on konfiguroitu isännäksi ja muuta laitteet orjiksi. Näitä laitteita ovat esim. lämpö-, kosteus- ja valoanturit.   RS485 koostuu monipisteverkosta, joka tukee useita laitteita. Yhtä isäntää kohden voi olla jopa 247 orjaa ja sitä voidaan käyttää jopa 1000 m etäisyyksillä korkeilla siirtonopeuksilla. RS232 puolestaan on ns. ”point-to-point” ratkaisu eli siinä on vain yksi isäntä ja yksi orja. Sen etäisyydet ovat alle 20 m ja siinä käytetään alhaisia tai keskisuuria nopeuksia. Kaikkien laitteiden on tuettava RS485-liitäntää, kun taas RS232 on valinnainen. (Hersent, et al., 2012; Sen, 2014; Seneviratne, 2017; Sousa & Portugal, 2011.)

Lähetysmuoto, joko RTU (Remote Terminal Unit) tai ASCII (American Standard Code for Information Interchange) määrittää Modbus-verkossa siirrettävien viestien rajauksen ja bittien koodauksen. Määrätyssä verkossa kaikkien solmujen on käytettävä samoja tila- ja sarjaparametreja. Molemmat sekä RTU-tila että ASCII-tila käyttävät tiedonsiirtoon asynkronista lähestymistapaa. Erona on kuitenkin se, että RTU:ssa jokainen kehyksen sisällä oleva tavu lähetetään käyttämällä 11-bittistä merkkiä, kun taas ASCII:ssa jokainen tavu lähetetään kahtena ASCII-merkkinä. RTU-tila on nopeampi kuin ASCII-tila ja siten se löytää enemmän sovelluksia viestien lähettämiseen kuin ASCII-tila. Modbus/TCP huolehtii pääsystä Modbus-toimintoihin. Jokainen pyyntö/vastaus lähetetään tunnetun 502 portin kautta, käyttäen isännän ja orjan välille muodostettua TCP-yhteyttä. Yhteys on uudelleenkäytettävissä.  (Hersent, et al., 2012; Sen, 2014; Sousa & Portugal, 2011.)

### Profinet

Vuonna 1989 aloittanut ja yli 20 vuotta markkinajohtajana ollut PROFIBUS & PROFINET Internationalin (PI) kehittämä Profinet on avoin teollisuuden Ethernet-standardi, joka kattaa kaikki automaatioteknologian vaatimukset. Profinet koostuu monista aiheista, kuten automaation distribuutiosta (Profinet CBA), kenttälaitteiden desentralisaatiosta (Profinet IO), verkon hallinnasta, asennusohjeistuksesta sekä verkkointegraatiosta. Alueellisesti ja maailmanlaajuisesti n. 1 700 jäsenyritystä tekee yhteistyötä automaation parantamiseksi. Vuodesta 2019 lähtien maailmassa on asennettu yli 32 miljoonaa Profinet-solmua. (About PI, 2020; J.Field, 2004; Henning, 2020; Wenzel, 2017.)

PROFINET CBA:ssa koneet ja järjestelmät on jaettu teknologisiin moduuleihin, jotka koostuvat mekaanisista ja elektronisista komponenteista, elektroniikasta sekä ohjelmistosta. Toiminnallisuus on koteloitu PROFINET CBA-komponentteihin. Standardisoitujen rajapintojen kautta saadaan yhteys näihin komponentteihin. Niitä voidaan yhdistellä tarpeen mukaan ja niitä voidaan helposti uudelleenkäyttää. PROFINET IO:n avulla desentralisoituja kenttälaitteita voidaan käyttää Ethernetin kanssa. Näin automaatiolaitteita voidaan helposti käyttää homogeenisessä verkkoinfrastruktuurissa (J.Field, 2004.)

Profinet-verkot saavuttavat 100 Mbit/s – 1Gbit/s (tai enemmän) suuruisia nopeuksia. Sanoman koko voi olla jopa 1 440 tavua, eikä osoiteavaruutta ole rajoitettu. Toisaalta ohjaimen suoritin ja muisti asettavat rajoituksia yksittäisille ohjaimille. Profinetin käyttämä kuluttuja- palvelumalli on joustavampi kuin isäntä/orja arkkitehtuuri. Sen verkossa sekä ohjaimet että IO-laitteet voivat ottaa kuluttajan ja palvelutarjoajan roolin hyödyntäen Ethernetin kaksisuuntaisuutta. Toimittajan roolissa ohjain toimittaa lähteviä tietoja konfiguroiduille IO-laitteille ollen IO-laitteiden syöttötietojen kuluttaja ja vastaavasti IO-laite on syöttötietojen toimittaja ja lähtevien tietojen kuluttaja. (Henning, 2020.)

Suorituskyvyn varmistamiseksi Profinet toimittaa tietoa seuraavien viestikanavien kautta:
-	TCP/IP (tai UDP/IP)
-	PROFINET Real-Time (RT)
-	PROFINET Isochronous Real-Time (IRT)
-	Time Sensitive Networking (TSN)

TCP/IP:tä käytetään ei-kriittisiin tehtäviin, kuten kokoonpanoon sekä parametrisointiin. Aikakriittisiin tehtäviin tämä menetelmä ei sovellu sillä IP-pohjaiseen viestintään liittyy lisäviivettä ja värinää. RT:ssa standardi Ethernet kehyksessä on EtherType-niminen kenttä, joka ilmaisee käytettävän protokollan tyypin, joka on 0x8892. Viestinnän nopeus ja determinismi paranevat huomattavasti sillä tiedot menevät suoraan Ethernetin 2. kerroksesta 7. kerrokseen ohittaen näin TCP/IP-kerrokset (Kuva 19). (Ayllon, 2021.)

![profinet](/assets/images/profinet.png)
##### Kuva 19: Profinet kerrokset. (Ayllon, 2021)

Profinet-tuotteet on varustettu siten, ettei mitään erityistä laitteistoa tai kokoonpanoa reaaliaikaisen mekanismin käyttämiseen tarvita. Suorituskykyä voi parantaa käyttämällä IRT:tä, joka eliminoi muuttujatiedon viiveet parantamalla Ethernet-liikenteen siirtämiseen käytettyjä sääntöjä ja luomalla erityissäännöt Profinet-liikenteelle. IRT on valinnainen ja se vaaditaan vain erityisissä korkean suorituskyvyn sovelluksissa, kuten pakkaus- ja painokoneissa. TNS on lupaavaa uutta tekniikkaa, jonka etuja ovat lähentyminen, skaalautuvuus sekä joustavuus. Se kykenee käsittelemään jopa 1 024 laitetta ja saavuttamaan 31.35 µs jaksonaikoja. Sen tavoitteena on yhdistää laaja valikoima IT-verkkoja automaatioverkkojen varmuuteen ja determinismiin. TSN:ää ei kuitenkaan vielä ole otettu käyttöön Profinet-komponenteissa. (Ayllon, 2021; Time Sensitive Networking... , 2021.)
<p>&nbsp;</p>  

# ROS tuettuja antureita

Erilaiset anturit kuuluvat jo melkein jokaisen arkeen. Antureilla mitataan lämpötilaa, etäisyyttä, ilman kosteutta, tasataan paineita ja havaitaan mahdollinen tulipalon aiheuttama savu tai häkä. Käyttökohteita ja tarkoituksia on lukemattomia. Anturit ovat laitteita, jotka mittaavat fyysistä syötettä ja muuntavat ne tiedoksi, jonka joko ihminen tai kone voi tulkita. ROS:in avulla robotti kehittää tietoisuutta ympäristöstään käyttämällä esim. stereonäköä, inertiamittausta sekä 3D-laserskannausta. Robotti yhdistää keräämänsä tiedot, jotta se tietää missä se on, minne se on menossa tai mitä mahdollisia esteitä on matkalla. (Stanley Innovation, 2020.) Hyvä listaus ROS antureita löytyy ROS wiki sivustolta: http://wiki.ros.org/Sensors. 
<p>&nbsp;</p>  

## Velodyne Lidar (Velodyne)

Velodyne on 1983 perustettu yritys, joka tarjoaa tehokkaimpia ja älykkäimpiä markkinoilla olevia etäisyydenmittauslaitteita autonomiaan ja kuljettajan avustukseen. LiDAR:a kutsutaan usein myös laserskannaukseksi tai 3D-skannaukseksi. LiDAR käyttää silmille turvallisia lasersäteitä muodostaakseen 3D-esityksen ympäristöstään (Kuva 20). (Velodyne Lidar, n.d.; What is LIDAR?, 2020.) 

![Velodyne1](assets/images/Velodyne.png)
##### Kuva 20:Velodyne simulointi Gazebolla

![Velodyne2](/assets/images/Velodyne_Rviz.png)
##### Kuva 21: Velodyne anturi visualisaatio Rviz:lla

Se laskee etäisyyksiä lähettämällä laservalopulssin ympäristöönsä ja laskee ajan, joka pulssilta kuluu heijastua kohteesta takaisin (Kuva 21). Toistamalla prosessia miljoonia kertoja sekunnissa saadaan tarkka reaaliaikainen 3D kartta. Velodyne voidaan liittää ROS:iin ja generoida pilveen pistetietoja raakadatasta. (Velodyne Lidar, n.d.; What is LIDAR?, 2020.) 

<p>&nbsp;</p>  
## ZED 2 kamera (Stereolabs)

Stereolabs on markkinoiden johtava 3D-syvyys- ja liiketunnistusratkaisujen toimittaja. Heidän tuotteensa perustuu stereonäköön sekä tekoälyyn. ZED 2 on ensimmäinen stereo kamera, joka käyttää neuroverkkoa tuottaakseen ihmismäisen näkymän. Siinä on sisäänrakennettu IMU (Inertial Measurement Unit), barometri sekä magnetometri, joilla se kerää reaaliaikaista synkronoitua inertia-, korkeus- ja magneettikenttädataa. Alkuperäisillä 16:9 antureilla ja 8-elementtisillä äärimmäisen terävillä linsseillä, joissa vääristymä on optisesti korjattu ja joissa on laajempi f/1,8 aukko, voi tallentaa videon ja syvyyden jopa 120° näkökenttään 40 % suuremmalla valomäärällä.(Built for the... , 2020)

![ZED](/assets/images/ZED_2.png)
##### ZED 2 visualisaatio Rviz:llä (Stereolabs Twitter, 2020)

<p>&nbsp;</p>  
## TeraRanger (Terabee)

Terabee perustettiin vuonna 2012 tarjoamaan innovatiivista dronepalvelua erityisen vaativiin tarkastuksiin. European Centre of Nuclear Research (CERN) näki vuonna 2013 mahdollisen potentiaalin ja tiedusteli, kykenisivätkö he kehittämään täysin autonomimisen dronen tutkimaan Large Hardon Colloder (LHC) tunnelia, joka on maailman suurin ja tehokkain hiukkaskiihdytin. Markkinoilla huomattiin olevan aukko ja nykyisin Terabee kehittää ja valmistaa monia erilaisia anturimoduleja kuten 2D-infrapuna LED (Light-Emitting Diode) ToF -etäisyysantureita (Time-of-Flight), 3D ToF syvyys- ja lämpökameroita. (Learn more about..., n.d) (The Large Hadron..., 2020) 

![Teraranger](/assets/images/TeraRanger.png)
##### TeraRanger Evo 60 m (Terabee, n.d)

<p>&nbsp;</p>  
## Xsense MTi IMU (Xsens)

Xsens on vuonna 2000 perustettu innovaatiojohtaja 3D-liikkeenseuranta- ja tallennusteknologiassa. Kuten nimikin sanoo perustuvat inertia-anturit inertiaan eli hitausmomenttiin. Ne vaihtelevat MEMS-inertia-antureiden muutaman neliömillin kokoisista erittäin tarkkoihin rengaslasergyroskooppeihin, joiden halkaisija saattaa olla jopa 50 cm kokoinen (Kuva ). IMU on muista riippumaton järjestelmä, joka mittaa lineaarista ja angulaarista liikettä kolmen gyroskoopin ja kiihtyvyysmittarin avulla. (xsens, n.d)

![Xsens](/assets/images/Xsens.png)
##### Xsens MTi (Xsens, n.d) 

<p>&nbsp;</p>  
## Hokuyo Laser (Hokuyo)

Hokuyo perustettiin vuonna 1946 Japanin Osakassa. Yritys tarjoaa automaatioteknologiaa kuten esim. laskureita, valosähköisiä antureita ja automaattisoituja ovia monille tehdasautomaatiojärjestelmille ja tuotantoprosesseille. (HOKUYO, 2014) 

![hokuyo](/assets/images/Hokuyo.png)
##### Hokuyo UST-20LX (ROS Components, 2016)
<p>&nbsp;</p> 

Esimerkiksi Hokuyo UST-20LX (Kuva ) on pieni, tarkka suurinopeuksinen skannauslaseri esteiden havaitsemiseen ja autonomisten robottien ja materiaalinkäsittelyjärjestelmiin. UST-20LX on tarkoitettu sisätiloihin ja sen kantama on 20 m, tunnistuskulma 270°, valaistusteho 15.000 luxia ja paino vain 130 g. (ROS components, 2016) 

<p>&nbsp;</p>  
## Microsoft ® Azure Kinect™ 

Azure Kinect on viimeisintä teknologiaa edustava spatiaalinen laskentasetti kehittäjille. Siinä yhdistyvät pitkälle kehittynyt konenäkö, puhemallit, kehittyneet tekoälyanturit sekä valikoima tehokkaita SDK:ita (Software Development Kit), jotka voidaan liittää Azuren kognitiivisiin palveluihin. Azure Kinect sisältää 1-MP syvyysanturin, jossa on mahdollisuus leveään ja kapeaan näkökenttään (engl. Field-of-view, FOV) valinnan mukaan. 7 elementin mikrofoniryhmän kaukoalueen puheen ja äänen keruuseen, 12-MP RGB videokamera, jolla saadaan syvyysvirtaan liitettävää ylimääräistä värivirtausta, kiihtyvyysanturi sekä gyroskooppi. Lisäksi se on helposti synkronisoitavissa monien Kinect-laitteiden kanssa ulkoisten synkronointitappien avulla. ROS-latenssilla on useita kehyksiä. Syksyllä 2020 julkaistiin tuki ROS2:lle sekä ARM64:lle. (Azure Kinect DK, 2020) 

![Azure](/assets/images/Azure.png)
##### Microsoft ® Azure Kinect™ (ROS-Industrial.org)
<p>&nbsp;</p>  

Laitetta hyödyntävät tuotanto-, vähittäismyynti-, terveydenhuolto- ja mediayritykset parantaakseen käyttöturvallisuutta, suorituskykyä, tuloksia sekä asiakaskokemuksia. (Azure Kinect DK, 2020) 

## Intel RealSense

Intel® RealSense™ D400-sarjan syvyyskamerat käyttävät stereonäkymää laskeakseen syvyyden. Stereokuva toteutetaan käyttämällä vasenta ja oikeaa kuvanninta sekä valinnaista infrapunaprojektoria. Matala tekstuurisissa näkymissä infrapunaprojektori heijastaa näkymätöntä staattista IR (Infrared) kuvioita parantaakseen syvyystarkkuutta. 

![Hokuyo](/assets/images/Intel_Realsense.png)
##### Aktiivinen IR Stereonäkö teknologia (Inter RealSense, 2020)
<p>&nbsp;</p> 

Kuvantimet tallentavat näkymän ja lähettävät datan syvyysnäköprosessorille, joka laskee kuvan jokaiselle pikselille syvyysarvot korreloimalla pisteitä keskenään ja siirtämällä pisteitä kuvien välillä. Syvyyspikseliarvot prosessoidaan syvyyskehyksen luomiseksi. Perättäisistä syvyyskehyksistä saadaan luotua syvyysvideostriimaus (Kuva  ). (Depth camera D415, 2020) 

<p>&nbsp;</p>  
# Alustat

Alustoja käytetään sovellusten, prosessien sekä teknologioiden kehittämisen pohjana. Valintaan vaikuttaa käyttötarkoituksen lisäksi moni seikka, kuten mm. tulo/lähtöjärjestelmät, rajapinnat, haluttu prosessorin nopeus, muistikapasiteetti sekä laajennusmahdollisuudet. Myös kaikki x86-arkkitehtuurin prosessorit ovat käytettävissä. Luvussa tutustutaan vain muutamaan soveltuvaan alustaan.  

### NVIDIA TX1/TX2

NVIDIA® Jetson™- järjestelmät nopeampaan autonomisten koneiden ohjelmistojen ajamiseen pienemmällä virrankulutuksella. Jokainen on kokonainen SOM-järjestelmä (System-on-Module), jossa on CPU (Central Processing Unit), GPU (Graphics Processing Unit), PMIC (Power Management Integrated Circuit), DRAM (Dynamic Random Access Memory) ja flash-muisti. Jetson on laajennettavissa valitsemalla sovellukselle sopivia SOM ja rakentamalla kustomoitu järjestelmä vastaamaan erityistarpeista. (Embedded Systems for..., 2020)

### Raspberry Pi 4

Viimeisin Raspberry Pi 4 Model B tarjoaa suorituskyvyn, joka on verrattavissa x86 pöytäkoneeseen. 64-bittinen neliydinprosessori, kahden näytön tuki 4K:n resoluutiolla mikro-HDMI porttiparin kautta, jopa 8 GB RAM-muistia, kaksitaajuinen 2.4 / 5 GHz langaton LAN (Local Area Network), 5.0 Bluetooth, Gigabitin Ethernet, USB 3 ja PoE (Power over Ethernet) ominaisuus erillisen lisäosan kautta. (Raspberry Pi 4..., 2020)

 
### Intel NUC

Intel® NUC (Next Unit of Computing) on pienikokoinen pöytäkone, joka tarjoaa suorituskykyä Celeronista Core i7:ään. Ensimmäiset laitteet tuotiin markkinoille 2013. Ytimenä toimii NUC Board emolevy, jossa on sisäänrakennettu suoritin. Intel HD tai Iris Graphics näytönohjain taas puolestaan on integroitu suorittimeen. Tehomalleissa on lisäksi integroitu Radeon RX Vega näytönohjain. Uusimmat NUC:it käyttävät DDR4 SO-DIMM muistimoduuleita 2400 MHz muistinopeuksilla. Ne tukevat kahden muistimoduulin käyttöä Dual Channel tilassa parantaen näin suorituskykyä. SSD (Solid State Drive) kiintolevyjä on saatavilla 2.5” SSD ja M.2 SSD. Intel NUC tukee sekä Windows 10 käyttöjärjestelmää että Linuxia. Ubuntulla ja siihen perustuvilla jakeluilla kuten esim. Mint on paras Intel NUC tuki. Molemmat käyttöjärjestelmät voidaan asentaa myös rinnakkain nk. Dual-boot tilaan.  (Intel NUC Ostajan..., 2020) 

### Odroid-XU4

Odroid-XU4 on yhden piirilevyn tietokone. Siinä on Samsung Exynos 5422 (4x Cortex-A15 @ 2.0GHz ja 4x Cortex-A7 @ 1.4GHz) suoritin, yhdistettynä Mali-T628 MP6 GPU ja 2 Gt RAM-muistiin. Se voi suorittaa Ubuntun ja Androidin uusimpia versioita. Ordroid-XU4:llä on erittäin suuri tiedonsiirtonopeus. Miinuspuolena voidaan mainita, että siitä puuttuu Wifi- tai Bluetooth yhteys, jotka ovat saatavana vain USB-dongleina. (Best Single Board..., 2020) 

<p>&nbsp;</p>  
# ROS:sin hyödyntäminen

Älykkäiden robottien suunnittelu ja rakentaminen ei ole niin yksinkertaista ja suoraviivaista kuin se voisi olla. Monet robotiikassa työskentelevät joutuivat usein aloittamaan aivan alusta aloittaessaan uuden projektin ja uudelleen kehittää ohjelmistoinfrastruktuurin joihin robottien algoritmit perustuvat. Jaetut työkalut ja resurssit olivat vähissä. ROS:sin etu on siinä, että suurimmassa osassa tapauksia ohjelmiston on jo todettu toimivan käytännössä. (Mok, 2020)

![ROS](/assets/images/yksikoiden_maara.png)
##### ROS käyttöjärjestelmiä käyttävien robottien maailmanlaajuisten yksiköiden määrän kasvu vuosina 2018–2024 (ROS-based robot..., 2018)
<p>&nbsp;</p> 

Yhteinen tietokanta on myös yksi avaintekijöistä ROS:in suosioon. Kuvasta --- nähdään ROS:iä käyttävien robottien maailmanlaajuisten käyttömäärien nousu vuodesta 2018 vuoteen 2024. (ROS-based robot..., 2018)
<p>&nbsp;</p> 

## Case-esimerkkejä maailmalta
<p>&nbsp;</p> 

## Teollisuusrobotit

ISO 8373:2012 mukaan teollisuusrobotti on autonomisesti ohjautuva, uudelleen ohjelmoitavissa oleva, moneen tarkoitukseen sopiva kolme tai useampi akselinen manipulaattori, joka voidaan asentaa joko kiinteästi tai käyttää mobiilina teollisuuden automaatiosovelluksissa. Näitä ovat mm. lineaari-, SCARA-, delta-, ja nivelrobotit. Koneoppiminen, tekoäly, IIoT (Industrial Internet of Things) sekä ihmisen ja koneen yhteistyö sekä autonomiset mobiilijärjestelmät ovat tätä päivää. Edessä on kuitenkin suuria haasteita, kuten nopeasti muuttuvat kuluttajasuuntaukset, resurssien puute, ammattitaitoisten työtekijöiden puute, ikääntyvä yhteiskunta ja paikallisten tuotteiden kysyntä. Joustava teollisuusrobotiikka mahdollistaa ratkaisun näihin haasteisiin. (World Robotics 2020, 2020)(Mueller, 2019) 
<p>&nbsp;</p> 

 
### MotoPlus ™ SDK ohjain 

Japanilainen Yaskawa Motoman oli yksi ensimmäisistä yhteistyö-, ja teollisuusrobottien valmistajista, joka hyödyntää ROS:sia. Yaskawa:lla on ROS-I ajuri YRC1000, YRC1000micro, DX200 ja DX100 robottien ohjaimiin. Ohjain kehitettiin käyttämällä MotoPlus™ SDK:ta (Kuva  ). Se sisältää C/C++ yhteensopivan ohjelmointirajapinnan (API, Application Programming Interface) jolla ohjelmoijat voivat tehdä reaaliaikaisia sovelluksia, jotka toimivat robotin alkuperäisessä VxWorks-käyttöjärjestelmässä. (Vozel, 2019) 

![Liikepaketti](/assets/images/Liikepaketin_kerrostumat.png)
##### Ros-Industrial liikepaketin kerrostumat sekä miten MotoROS ja Yaskawa Motoman ohjain liittyvät toisiinsa
<p>&nbsp;</p> 

Rajoitettujen sovellusten kehittäminen voimanhallintaan, visuaaliseen robotin ohjaukseen sekä geneeriseen anturien integrointiin mahdollistuu. (Specific Unified Robot Description Formats (URDF) on saatavana robottien käsivarsien simulointiin. (Vozel, 2019) 


<p>&nbsp;</p>  
### Plug’n’play ROS-ohjain 

Tanskalainen Universal Robots on hallitseva kevyiden käsivarsirobottien toimittaja sekä teollisuuteen että tutkimukseen ja opetukseen. Tutkimuskenttä on kehittänyt kolmansien osapuolien ohjaimia, joilla ROS yhteisö on voinut kommunikoida UR robottien kanssa. ROS yhteisöstä löytyy yli 200 haaraa, jotka ovat UR yhteensopivia. UR ei silti koskaan ole ollut kehittämässä tai tukemassa näitä ohjaimia. Saatavilla on monia yhteisön kehittämiä ohjaimia, joista ei tiedä millä niistä on viimeisimmät ominaisuudet tai mitkä niistä tukevat oikeaa UR ohjelmaversiota. (Madsen, 2019) 


![Universal](/assets/images/Universal.png)
##### Universal robots:in e-sarjalaiset (Meet the e-Series..., 2020)
<p>&nbsp;</p> 

Jotta Universal Robots: in parhaita ominaisuuksia hyödynnettäisiin, kehittivät he yhteistyössä saksalaisen tutkimuslaitoksen, FZI (Forschungszentrum Informatik, Research Center for Information Technology) kanssa Universal Robots: in tukeman ROS-ohjaimen, jotta siitä saatiin vakaa ja kestävä. Ohjain julkaistiin markkinoille lokakuussa 2019. Tämä on ”plug’n’play”-tyylinen, helppokäyttöinen ohjain UR roboteille. Se hyödyntää robotin pääominaisuuksia, jotta se kykenee parhaaseen suorituskykykyynsä ja tarjoaa parhaimman teollisuusluokan rajapinnan, jonka nykyinen ROS käytäntö mahdollistaa. Ohjain sisältää spesifit robotin kalibrointidatat parhaaseen tarkkuuteen. Ohjain tulee olemaan avoin lähdekoodi ja nojaa tulevaisuuden yhteisökehitykseen. Ohjain on tarkoitettu CB3 ja e-sarjalaisille, joissa RTDE (Real-Time Data Exhange) on saatavilla (Kuva  ). (Madsen, 2019) (Universal Robots ROS..., 2020)


<p>&nbsp;</p>  
### ROSweld hitsausjärjestelmä

Norjalainen robottijärjestelmien integraattori, PPM Robotics on kehittänyt ROSweldin (Kuva  ) joka on ensimmäinen raskasrobottihitsausjärjestelmä jossa käytetään koneoppimista monipalkohitsauksen suunnittelussa ja mallinnuksessa. ROSweldiin kuuluu myös suunnittelu CAD-malleista, graafinen monipalkohitsauksen poikkileikkauksen käsittely, simulointi sekä hitsauskameran integraatio. Konenäköjärjestelmä käyttää FlexGui 4.0:aa käyttöliittymänä, jolla voidaan uudelleenohjelmoida työstettävät kappaleet, filtteri, parametrit sekä toistot. ROS-alustasta johtuen näköjärjestelmä on robotti ja kamera riippumaton. (Santos, 2020) 

![ROSweld](/assets/images/ROSweld.png)
##### ROSweld järjestelmä PPM Robotics:lta (Santos, 2020) 

<p>&nbsp;</p>  
ROSweld järjestelmässä jokainen komponentti on solmu tarjoten saman toiminnallisuuden ohjainryhmässä. Eri moduuleille on vakaa viestintäkerros ja standardit. MoveIt!, Rviz, RobotWebTools ROS2d.js, PCL (Point Cloud Library), pyros sekä rosbridge ovat käytössä olevia komponentteja. (Thomessen, 2018) 

![Rakenne](/assets/images/ROSweld_järjestelmä.png)
##### Järjestelmän rakenne (Thomessen, 2018)

<p>&nbsp;</p> 
### Teollisuuden yhteistyörobotit

Limor Schweitzer perusti portugalilaisen MOV.AI:in vuonna 2016. Yritys keskittyy robottijärjestelmien tekoälyyn, logistiikka-automaatioon sekä kalustonhallintaan ROS:iin pohjautuen. Yhtiön ajatuksena on muuttaa mikä tahansa ihmisen käyttämä materiaalinkäsittelykone autonomisesti toimivaksi älykkääksi yhteistyörobotiksi, cobotiksi. Monotoniset tehtävät jäävät siten robottien tehtäväksi ja ihmiset voidaan siirtää suorittamaan monimutkaisempia ja vaativampia tehtäviä. MOV.AI tarjoaa kehittäjille ja automaatiointegraattoreille ohjelmistojen kehitysalustan, joka säästää n. 10 henkilötyövuotta kehitettäessä eri käyttöön tarkoitettuja robotteja. Ainutlaatuisen graafisen käyttöliittymän muita ominaisuuksia ovat autonominen navigointi, esteiden välttäminen sekä vaatimusten mukainen turvallisuus (Kuva   ). (MOV.AI - The Robotics..., 2020) (Limor Schweitzer, MOV.AI’s..., 2019) (Ingham, 2020) (MOV.AI Raises $4M..., 2020) 

Lokakuun 13. päivä 2020 MOV.AI ilmoitti keränneensä 4 M$ rahoituksen yhteistyörobottien käyttöjärjestelmien kehittämiseen. Kokonaisuudessaan yrityksen pääoma on 8 M$. Varainhankintaa johti SOMV (State of Mind Ventures) ja lisärahoitusta myönsivät nykyiset sijoittajat NFX ja Viola Ventures. Yrityksen asiakkaista suurin osa tulee Länsi-Euroopasta, kuten Saksasta, Tanskasta, Ruotsista, Irlannista, Ranskasta sekä Yhdistyneistä kuningaskunnista. Sillä on myös joitakin asiakkaita Singaporessa sekä Yhdysvalloissa. (Ingham, 2020) 

![mov](/assets/images/mov.ai.png)
##### MOV.AI ROS. (mov.ai, n.d)
<p>&nbsp;</p> 

MOV.AI tekee useita parannuksia ROS:iin, nopeuttaen näin robottien käyttäytymisen ja kaluston automatisointiin tarvittavaa kehitysaikaa. Alla MOV.AI:in esittelemät muutokset: 

Visual ROS Launch system (Kuva  ) 

- Replaces roslaunch / rosrun framework with Visual Launch Diagrams 
- Multi-protocol node launcher, in-browser 
- Drag & Drop Nodes, Connect Node inputs/outputs 
- VLD lines represent communication protocols between nodes 
- Modify Nodes/connections in split seconds 
- Organize multiple Node networks, Node versions & Parameters 
- Supports all ROS features including TF, Nodelets, pluginlib, lifecycle 

  ![mov](/assets/images/visual_system.png)
  ##### ROS Visual Launch system (mov.ai, n.d)
  <p>&nbsp;</p> 

MOV.AI Nodes – IDE in Browser (Kuva  ) 

- Multi-Protocol Event processor 
  - Message/Event triggers Callback in Python 
  - Support for ROS1, ROS2, HTTP, WebSocket, Serial Driver, Redis DB 
  - Callback code cannot access communication layer 
- Native parallel processing;  
  - Callbacks are Re-entrant – Persistent data only via Redis DB API 
  - AsyncIO backend + Cython (C level performance) 
  - Resource Usage Profiling tools 
- Upgrade / Downgrade – mandatory for industrial clients 
  - Imported libraries – outside the callback code 
  - GIT based versioning of Callbacks 

  ![mov](/assets/images/IDE.png)
  ##### IDE selaimessa (mov.ai, n.d)
  <p>&nbsp;</p> 

Customizable UI (Kuva  ) 

- Modern MVC framework; 
  - Collaborative UI (2-direct. link w db replicated on every robot) 
  - Any Robot can act as Web server 
- Extensible web API 
  - HTTP/WebSockets protocols supported in MOV.AI Nodes 
  - Custom server-side functions 
  - REST API available for CRUDE actions (vs replicated DB) 
- REST-full application 
  - Develop apps with preferred js framework (React, Vue, etc) 
  - Upload your own javascript application to Mov.AI system 
- Dashboard Creator 
  - Create operator views with stats and queues 
  - Create custom dashboards to monitor and control fleets 
  - Extensible set of customizable widgets 

  ![mov](/assets/images/muunneltava_UI.png)
  ##### Muunneltava UI (mov.ai, n.d)
  <p>&nbsp;</p> 

State Transitions 

  - Mix Nodes and State Machine in single view 
  - Visual Launch Diagrams can act as State Machine Diagrams 
  - MOV.AI Nodes can act as “State Nodes” 
  - When a Node is transitioned-to, all non-connected nodes are recursively 
    killed/disabled 
  - Visualize dependency between Robot’s State & required ROS nodes 
  - Visual ROS2 lifecycle manager 

(Mov.ai, n.d) 

<p>&nbsp;</p>  
## Autonomiset ajoneuvot

Määritelmän mukaan ajoneuvo, joka havainnoi ja tunnistaa ympäristönsä sekä kykenee toimimaan itsenäisesti, luokitellaan autonomiseksi (Kuva  ). Autonominen auto käyttää erilaisia tekniikoita ympäristönsä havaitsemiseen. näitä ovat mm. tutka, laservalo, GPS (Global Positioning System), odometri, konenäkö ja monet muut. Autonomisten ajoneuvojen haasteita ovat ja tulevat edelleen olemaan lokalisointi, kartoitus, näkymän havainnointi, ajoneuvon hallinta, liikeradan optimointi sekä korkeatasoiset ennakoivat päätökset. Autonomisen ajamisen tasoja on viisi:  

Taso 1: kuljettajan avustus, josta mainittakoon esimerkkinä vakionopeuden säädin sekä kaista-avustin. 

Taso 2: osittainen automaatio, jossa auto voi liikkua ilman kuljettajan ajoon puuttumista, mutta kuljettajan on pidettävä käden auton ratissa ja kuljettajalla on vastuu.  

Taso 3: ehdollinen automaatio antaa jo kuljettajalle vapauden keskittyä vaikka puhelimen tai videoiden katseluun. Nukkuminen ei tosin vieläkään ole sallittua. 

Taso 4: korkea automaatio, jossa auton tuli selviytyä suurimmasta osasta ajotilanteita itsenäisesti. Kuljettajan on kuitenkin oltava valmiina ottamaan auto hallintaa hälytettäessä, mikäli näin ei tapahdu. auto ohjautuu itse tien sivuun ja pysähtyy. 

Taso 5: täysi automaatio, jossa kuljettajaa ei enää tarvita. 

(Kokkonen, 2020) 

Vielä tänä päivänä on kaikissa itseajavissa autoissa oltava mukana ihmiskuljettaja, joka on valmis ottamaan ohjat tarvittaessa.  (Fridman, et al., 2017) (Suresh, et al., 2018) 

![Komponentit](/assets/images/Autonomisen auton komp.png)
##### Autonomisen auton tärkeitä komponentteja (Mahtani & al., 2018)
<p>&nbsp;</p> 

Volvo Car Group:in teknologiajohtaja Henrik Green:in mukaan täysin autonomisilla ajoneuvoilla on potentiaalia parantaa liikenneturvallisuutta tasoon, jota ei ole aiemmin nähty ja mullistaa tapa, jolla ihmiset elävät, työskentelevät ja matkustavat. (Cuneo, 2020) 

<p>&nbsp;</p>  
### Autonominen kuorma-auto

Yhdysvaltalainen Embark on vuonna 2016 perustettu kahden nuoren kanadalaisen tietokone tutkijan startup San Franciscossa. Yritys toimii yhteistyössä Electroluxin ja Ryderin kanssa ja kehittää autonomisten kuorma-autojen (Kuva  ) teknologiaa, jossa kuorma-autot kulkevat maanteillä ilman kuljettajaa, täysin itsenäisesti jopa 1046 km matkan. Heidän kokonaisrahoituksensa on 117M $, josta 70M $ tuli vuonna 2019. Erilaisia tutkia, kameroita ja syvyysantureita, kuten LiDAR:ia käyttämällä miljoonat saadut datapisteet käsitellään neuroverkolla, Deep Neural Nets (DNN). Näin kuorma-auto kykenee oppimaan kokemuksistaan kuten ihmisetkin. Terabittejä reaalimaailman dataa analysoituaan neuroverkko oppii itsenäisesti tunnistamaan häikäisyn, sumun ja pimeyden. (Fleet Owner, 2017)  (Ohnsman, 2019) (Sushant, 2019) 

![Embark](/assets/images/Autonominen kuorma-auto.png)
##### Embark kuorma-auto
<p>&nbsp;</p> 

Embark Trucks toimii nykyisin tason kaksi autonomiana. Erikoisvalmisteinen, kaksoisredundantti tietokone, joka testaa itsensä satoja kertoja sekunnissa tarkkailee jokaista komentoa reaaliajassa. (Sushant, 2019) 

<p>&nbsp;</p>  
### Autonomisten autojen Rosbag-data

Yhdysvaltalainen Ford Motor Company on vuonna 1903 perustettu yhtiö, joka on valmistanut T-mallin, Continentalin, Mustangin ja Broncon. He ovat valmistaneet myös lentokoneita, radioita, jääkaappeja, postituskoneita sekä sääsatelliitteja. Maaliskuussa 2020 Ford julkisti kaikessa hiljaisuudessa kokoelman, joka sisältää useiden eri autonomisten autojen datan – Ford Autonomous Vehicle Dataset. Data on kerätty eri päivinä ja aikoina vuosina 2017-2018. Ajoneuvot kulkivat keskimäärin 66 km: n reitin ja jokaisessa oli Applanix POS-LV GNSS- järjestelmä, neljä HDL-32E Velodyne 3D-lidar skanneria, kuusi 1,3 MP harmaapiste kameraa katolle asennettuna 360 asteen peittoa varten ja yksi 5 MP: n harmaapiste kamera tuulilasin taakse asennettuna suoraan eteenpäin kohdistuvan näkymän varmistamiseksi. Auton takaluukkuun sijoitettiin neljä Quad -core i7-prosessoria, joissa oli 16 Gt RAM, verkkolaitteet ja jäähdytysmekanismi. (Wiggers, 2020) 

![Rosbag](/assets/images/Rosbag.png)
##### Yhteenveto Rosbag-viesteistä (Agarwal & al., 2020)
<p>&nbsp;</p> 

Aineiston jälkikäsittely suoritettiin kannettavalla Dell Precision 7710 tietokoneella. Kaikki tieto on saatavissa Rosbag-muodossa (Kuva  ), jota voidaan visualisoida ja muokata ROS:sin avulla. He toivovat, että tämä monen vuodenajan aineisto tulisi olemaan hyödyllinen robotiikalle ja AI-yhteisölle sekä tarjoamaan uusia tutkimusmahdollisuuksia. (Wiggers, 2020) 
<p>&nbsp;</p> 

### Korkean teknologian ratkaisuja automatisoituihin ja kytkettyihin ajoneuvoihin 

Puolalainen Robotec.ai on ajoneuvojen prototypointiin, ajoneuvojen testaukseen ja kehitykseen keskittynyt teknologiayritys. Havaitsemiseen, suunnitteluun sekä ajoneuvon hallintaan käytetään erilaisia simulointitekniikoita. Palveluvalikoima on jaettu robotiikkaan, sisäiseen havainnointiin sekä tekoälyyn. (Robotec.ai, 2021) 

Yhdessä Tier IV:n kanssa he ovat mm. yhdistäneet ROS2-ekosysteemin ja Unity3D-simulaatiot. ROS2 For Unity (R2FU) on tarkoitettu käyttäjille, joille suorituskyky ja nopea simulaatio, erityisesti suurilla datansiirroilla on tärkeää. R2FU ei vaadi ylimääräisiä päätepisteitä ja se kommunikoi suoraan muiden ROS 2-solmujen kanssa, huomioiden DDS-toteutuksen CycloneDDS ja FastRTPS välillä sekä tilaajien ja julkaisijoiden QoS asetukset. R2FU:n avulla voidaan simuloida erilaisilla antureilla varustettuja ajoneuvo- tai robotti parvia (Kuva  ). ROS 2 paketit voivat vastaanottaa simuloituja tietoja pienemmillä viiveillä, pitäen suurikapasiteettiset taajuudet ja kokonaiskäyttäytymisen parempana. (Dabrowski, 2021) 

![ROS2Unity](/assets/images/ROS2ForUnity.png)
#####  ROS2 For Unity (Dabrowski, 2021) 
<p>&nbsp;</p> 

Apex.AI, Open Robotics, ADLINK sekä Tokion yliopisto ovat valinneet Robotec.ai:n parantamaan rosbag2:n suorituskykyä. Käyttöön otettiin puskuroitu asynkroninen kirjoitus sekä taustaoptimointi. Samalla korjattiin joitain vakausongelmia ja lisättiin uusi ominaisuus tallennetun datan suodatukseen. (Dabrowski, 2021) 
<p>&nbsp;</p>  

### Autoware.AI ja Autoware.Auto 

Tohtori Shinpei Kato Japanin Nagoya yliopistolta kehitti ja lanseerasi alkuperäisen Autoware.AI:n vuonna 2015. Samana vuonna perustettiin Tier IV etsimään autonomisen ajamisen markkinasegmenttien mahdollisuuksia. 2018 Tier IV siirsi kaikki Autowaren oikeudet juuri perustetulle voittoa tavoittelemattomalle Autoware-säätiölle (Autoware Foundation, AWF).  AWF:n muita perustajajäseniä olivat Apex.AI sekä Linaro 96Boards. (What is autoware?, 2020) 

![Autoware](/assets/images/Autoware.png)
##### Autoware ekosysteemi, (Autoware.AI, 2021)
<p>&nbsp;</p> 

Autoware.AI on maailman ensimmäinen ”All-in-One” ROS 1 avoimen lähdekoodin ohjelmisto autonomiselle ajotekniikalle (Kuva  ). Lokalisointi tapahtuu 3D-karttoja ja SLAM-algoritmeja käyttäen yhdessä GNSS- ja IMU-antureiden kanssa. Tunnistukseen käytetään kameroita ja LiDAR-laitteita, joissa on anturifuusioalgoritmeja sekä syviä neuroverkkoja. Ennustus ja suunnittelu perustuvat todennäköisyyspohjaiseen robotiikkaan sekä sääntöihin perustuvaan järjestelmään, joissa myös osittain käytetään syviä neuroverkkoja. Autoware.AI:n seuraaja on Autoware.Auto joka perustuu ROS 2. Merkittävimpiä eroja Autoware.AI:n ja Autoware.Auton välillä ovat nykyaikaiset ohjelmistosuunnittelun parhaat käytännöt kuten koodiarvostelut, jatkuva integraatiotestaus, perusteellinen dokumentointi ja testikattavuus sekä tyyli- ja kehitysoppaat. Parannettu järjestelmäarkkitehtuuri sekä moduulikäyttöliittymän suunnittelu. Kirjaston solmu- ja järjestelmä tason toistettavuuden ja determinismin korostus. (Autoware.Auto, n.d.) (Autoware.AI, 2021)  
<p>&nbsp;</p>  

### LettuceBot

Vuonna 2017 maatalous- ja ympäristönhoitokoneita valmistava John Deere osti Blue River Technology nimisen ROS:ia maataloustyöhön käyttävän yrityksen 305 miljoonalla dollarilla. Blue Riverin automaattinen tietokonenäköjärjestelmä tappaa ei-toivotut salaatit tarkasti annetulla lannoitteen yliannostuksella. Salaattien pitää olla riittävän lähellä toisiaan itääkseen, mutta toisaalta joitakin niistä on poistettava, jotta toiset voivat kasvaa. LettuceBotin avulla salaatin ”ohentaminen” käy tehokkaammin. LettuceBot kykenee ohentamaan 6 hehtaarin tontin vain muutamassa tunnissa. Saman työn tekemiseen menisi 50 työntekijältä 2 päivää. Mikäli jotain ongelmia ilmenee, tarkistetaan nopeasti ROS-koodin solmut ja kehitetään ongelmaan ratkaisu. (Hornyak, 2014) (Robot Operating System..., 2021)​ 

![lettucebot](/assets/images/lettucebot.png)
##### John Deere ja LettuceBot (Robot Operating System…, 2021)
<p>&nbsp;</p> 

John Deere myy jo tekniikkaa, joka GPS:n avulla automatisoi maatalousajoneuvojen liikkeitä pelloilla, alle tuuman tarkkuudella. Älykkäitä ratkaisuja käsittelevän ryhmän johtaja John Stone, sanoo, että Blue Riverin tietokonenäkötekniikka auttaa Deeren laitteita näkemään ja ymmärtämään viljelykasveja, joiden kanssa ne työskentelevät. Tavallinen traktori vetää robottia perässään tavallisen ruiskutuslaitteen tapaan. Robotissa on kuitenkin koneoppimisohjelmistoa käyttävät kamerat viljelykasvien ja rikkaruohojen erottamiseen (Kuva  ). (Simonite, 2017) 

Yrityskaupoista huolimatta Blue River jatkaa toimintaansa itsenäisenä brändinä ja se aikoo kehittää tekniikastaan versioita muillekin viljelykasveille, kuten soijapavuille ja maissille. Järjestelmä kohdistaa torjunta-ainetta rikkaruohoon, joka on vain postimerkin kokoinen. Blue Riverin uuden teknologian johtaja Willy Pellin mukaan järjestelmä voi vähentää rikkakasvien torjunta-aineiden käyttöä 90 %. Yritys on myös testannut toisenlaista puuvillanviljelijöille tarkoitettua järjestelmää. (Simonite, 2017) 

<p>&nbsp;</p>  
## Autonomiset mobiilirobotit (Autonomous Mobile Robots, AMRs) 

Mobiilirobotteja käytetään teollisuudessa, kotitalouksissa ja erilaisissa palvelutoiminnoissa. Ne ovat tunnettuja uniikista kyvystään navigoida kontrolloimattomassa ympäristössä sensoreiden, piirustusten, tekoälyn, 3D- tai 2D-näön tai vastaavan kautta. ”AMR:t eivät vain kulje paikasta A paikkaan B, vaan niiden havaintokyky sallii uudelleenreitityksen, mikäli jokin este tulee niiden eteen.” sanoo Matt Wicks tuotekehityksen varajohtaja Honeywell Intelligent: sta. (Zenner, 2019) 

COVID-19 pandemia muutti Yhdysvaltojen pitkäaikaista trendiä, jossa autonomiset robotit päätyivät pääasiassa autoteollisuudelle. Ihmisten ostaessa tuotteita verkosta pandemia myös vauhditti automaation pitkäaikaista suuntausta, jossa verkkokauppiaat lisäävät kapasiteettiaan ja tehtaat käyttävät automaatiota pitämään tuotantolinjat toiminnassa ja työntekijät turvaetäisyyksien päässä toisistaan. Association for Advancing Automationin mukaan robottitoimitukset lisääntyivät vuonna 2020 3,5 % edellisvuoteen verrattuna ja niistä 52 % menee laitoksiin, jotka valmistavat kulutustavaroita ja lääkkeitä. Näiden tilausten arvo oli 1.57 miljardia dollaria. Pandemian alkuvaiheessa keväällä 2020 robottiteollisuus joutui koetukselle maailmanlaajuisten toimitusketjujen katketessa ja yritysten sulkeutuessa. Ala ponnahti kuitenkin takaisin myöhemmin samana vuonna toimitusten ollessa historiallisen korkeita. Autoteollisuus on pitkään hallinnut robottien markkinoita, mutta sittemmin ovat muut teollisuudenalat saaneet enemmän jalansijaa kuvastaen halvempien ja mukautumiskykyisten robottien kehittymistä. (Reuters, 2021) 

<p>&nbsp;</p> 
### Relay-palvelurobotti

Yhdysvaltalainen Savioke on vuonna 2013 perustettu yritys, joka kehittää ja valmistaa autonomisia palvelurobotteja. Sen lippulaiva on Relay niminen robotti (Kuva   ), joka käyttää sisäistä karttaa ja LiDAR:ia liikkuakseen ihmisten parissa. Suomalainen hissivalmistaja KONE tekee Savioke:n kanssa yhteistyötä huippuluokan hotelleissa. Tulevaisuudessa hotelleissa ei tarvitse olla mitään ylimääräisiä asennuksia sillä Relay ja hissit tulevat käyttämään KONE:n Flow Connectivity- ja pilvipalveluita, jolloin Relay kommunikoi KONE:n IoT alustan kanssa. (The robot butler..., 2018)  

![Relay](/assets/images/Relay.png)
##### Savioke, Relay (Relay, 2020)
<p>&nbsp;</p> 

Yhtiö sai vuonna 2018 13.4M $ rahoituksen laajentaakseen tuotteensa sairaaloihin, joissa Relay voi auttaa sairaanhoitajia, laboratorioteknikoita ja muita terveydenhuollon ammattilaisia toimittamalla esim. näytteitä, lääkkeitä ja tarvikkeita. (Johnson, 2018)  

<p>&nbsp;</p>  
### Moxi-mobiilirobotti manipulaattorilla

Yhdysvaltalainen Diligent Robotics perustettiin vuonna 2017 sosiaalisen robottiteollisuuden asiantuntijoiden toimesta. He ovat luoneet Moxi-mobiilirobotin, jossa on manipulaattori ja johon yhdistyy sosiaalinen älykkyys sekä ihmisohjatut oppimismahdollisuudet. Moxi toimii sairaaloissa auttaen hoitajia ei-potilas-hoidollisissa tilanteissa, jolloin hoitajille jää enemmän aikaa itse potilaiden hoitoon. Näitä tehtäviä ovat mm. tarvikkeiden kerääminen, potilaslaboratorionäytteiden ja päivittäisten liinanvaatteiden toimittaminen sekä esineiden hakeminen keskusvarastosta. (Kara, 2020) (Diligent robotics, n.d) 

![Moxi](/assets/images/Moxi.png)
##### Moxi-mobiilirobotti manipulaattorilla (Diligent Robots, n.d)
<p>&nbsp;</p> 

Moxi parantaa tehokkuutta, lisää työntekijöiden tyytyväisyyttä sekä parantaa hoidon laatua. Robotti käyttää koneoppimista kohteiden tunnistukseen ja tarttumiseen sekä ROS:iin perustuvaa navigaatio-ohjelmistoa. Siinä on osia eri laitevalmistajilta kuten Fetch Robotics, Velodyne Lidar, Intel, Kinova ja Robotiq. (Kara, 2020) (Diligent robotics, n.d) 

<p>&nbsp;</p>  
### Windows IoT tuki Jackal UGV:lle

Kanadalainen Cleatpath Robotics on neljän yliopistokaveruksen kellarista vuonna 2009 ponnistanut, palkittu, johtava miehittämättömien robottiajoneuvojen valmistaja maailmalla. Heidän tuotteitaan käytetään maataloudessa, kaivostoiminnassa, teollisuudessa, asevoimissa ja eri tutkimusaloilla. Toukokuussa 2020 Clearpath ilmoitti aloittavansa Windows IoT Enterprise tuennan, alkaen Jackal UGV:sta (Unmanned Ground Vehicle). Jackal (Kuva  ) on pieni, kestävä mobiilirobotti, jota voidaan käyttää ympäristön etävalvonnassa ja -tarkastuksissa tilanteissa, jotka vaativat navigointia ulkona ja/tai ihmisen ja robotin vuorovaikutusta. Siinä on sisäänrakennettu tietokone, GPS sekä IMU, joka on integroitu ROS:iin käyttövalmiin autonomian vuoksi. Se on valmistettu tukevasta alumiinirungosta, siinä on suuri vääntömomentti 4 x 4 voimansiirrolla tehden siitä soveltuvan vaikeisiinkin maasto-olosuhteisiin. Siinä on IP62 luokituksen omaava kotelo ja sen kykenee operoimaan -20 °C - 45°C lämpötiloissa. (Jackal unmanned ground..., n.d)(Microsoft Corporation, 2020)  

![Jackal](/assets/images/Clearpath Robots, JACKAL.png)
##### Clearpath Robots, JACKAL (Jackal unmanned ground..., n.d)
<p>&nbsp;</p> 

Windows 10 Enterprise tuo mukanaan hyötyjä kuten yritysluokan suojauksen, helpon yhdistettävyyden pilveen, enemmän älykkyyttä Windows:in ML ROS noden kautta sekä nopeamman kehityksen. (Clearpath robots on..., 2020)      

<p>&nbsp;</p>  
### Tavaroiden toimitusrobotti

Starship Technologiesin kuusipyöräinen, ostoskorin kokoinen mobiilirobotti toimittaa mm. paketteja ja ruokatilauksia toimien jo monilla yhdysvaltalaisilla yliopistokampuksilla ja useissa eri maissa. Robotti kulkee kävelyvauhtia ja sen kantama on n. 6 km eikä se paina kuin 45 kg, sen kantokyvyn ollessa n. 9 kg (Kuva   ). Taukojen tarpeettomuus kompensoi sen kulkuhitautta. Lataamalla Starship Deliveries-sovelluksen kuluttaja voi tehdä tarjolla olevista tuotteista tilauksen haluamaansa toimituspaikkaan. Robotin kulkua voi seurata interaktiivisen kartan avulla. Saavuttuaan haluttuun pisteeseen robotti ilmoittaa tilaajalle saapumisestaan ja tilaaja voi avata robotin kannen sovelluksen avulla. (The Self-Driving Delivery..., n.d) (Korosec, 2020) 

![starship](/assets/images/Starship.png)
##### Starship robotti (Hawkins, 2019)
<p>&nbsp;</p> 

Skypen perustajat Ahti Heinla ja Janus Friis perustivat Starship:in vuonna 2014. Yrityksen päämaja on San Franciscossa ja pääkonttori Virossa. Sillä on myös konttori Helsingissä, jossa on mm. ohjelmistotuotantoa. Viimeisen rahoituskierroksen päätyttyä Starship on kerännyt yhteensä 85 M$. Sijoittajia ovat mm. Morpheus Ventures, Shasta Ventures, Matrix Partners, MetaPlanet Holdings, TDK Ventures sekä Qu Ventures  (A revolution in..., n.d)(Hawkins, 2019) 

Robotti käyttää vähintään 9 kameraa mukaan lukien 6 spektri kameraa sekä kolmea 3D ToF-kameraa. Konenäköön ja autonomisten ajotoimintojen suorittamiseen se käyttää Nvidia Tegra K1 -mobiiliprosessoria sekä 360° näkymällä varustettuja ultraääniantureita sekä GPS- ja IMU-kiihtyvyysanturia. Henlan mukaan akkukäyttöiset robotit käyttävät vähemmän energiaa kuin suurin osa hehkulampuista. Mikäli jotain menee pieleen, kykenee operoija ottamaan ohjauksen hallintaansa ja näkemään maailman robotin ”silmin”. Robotti on varustettu mikrofoneilla ja kaiuttimilla, joten se kykenee kommunikoimaan tapaamiensa ihmisten kanssa. Robotti käyttää samankaltaista teknologiaa kuin autonomiset autot, mutta paljon halvemmalla. Robotin on suunnitellut pohjoismainen Aivan ja se on voittanut Kaj Franckin muotoilupalkinnon 2019. (Kottasova, 2015) (Autonomous robot successfully..., 2017) (Introducing the revolution..., n.d) (Starship Technologies-kuljetusrobotti..., 2019) 

![starship](/assets/images/starship_maailma.png)
##### Starshipin toimitukset maailmanlaajuisesti (Heinla, 2021)
<p>&nbsp;</p> 

Kuusi vuotta perustamisensa jälkeen Starship on toimittanut jo yli miljoona tilausta ja heillä on useita toimialueita Yhdysvalloissa ja Euroopassa (Kuva  ). (Heinla, 2021) 

<p>&nbsp;</p> 
### Kompano Deleaf-Line robotti 

Puutarhayritysten tarvitsema työvoima on merkittävä kustannuserä ja työvoiman saatavuus on rajallista ja haasteellista. Vuonna 1959 Alankomaiden Westlandissa perustettu Priva on kehittänyt Kompano robotin, joka poistaa kasvihuonetomaattien varsista lehtiä ja vähentää siten työvoiman tarvetta (Kuva  ). (Expertise Horticulture, n.d) (The Kompano Robot..., 2019) 

![kompano](/assets/images/Kompano.png)
##### Kompano Deleaf-line robot (The Kompano Robot..., 2019)
<p>&nbsp;</p> 

Robotti esiteltiin GreenTechissä 2016. Yksi robotti kykenee suoriutumaan 0.75–1 hehtaarin alueesta, riippuen varsien tiheydestä. Se kulkee kasvihuoneeseen asennettuja putkikiskoja pitkin ja kykenee tunnistamaan poistettavat lehdet stereoskooppikameraparilla, toimien monenlaisissa eri valaistuksissa. Kamerat räätälöitiin tarpeisiin sopivaksi kahdesta FLIR Integrated Imaging Solutions Chameleon3 kameraparista. Kameroissa on 1,3 megapikselin puolijohde PYTHON 1300 CMOS -kenno 4,8 µm pikselikoko ja se voi ottaa jopa 149 kuvaa sekunnissa (Kuva   ).(Expertise Horticulture, n.d) (The Kompano Robot..., 2019) (Vision-guided robot trims..., 2017) 

![kompano](/assets/images/kompano_kamera.png)
#####  Robotin käyttämä pari stereoskooppi kameroita asennettuna liikkuvalle alustalle. (Vision-Guided Robot Trims..., 2016) 
<p>&nbsp;</p> 

Niillä saadaan laaja näkökenttä sekä tomaatin oikealta, että vasemmalta puolelta. Järjestelmässä käytetään Xenon strobe valoa valaisemaan kasveja. Strobo lähettää valoa 2 sekunnin välein, jolloin se laukaisee stereokamerat 30 mikrosekunnin välein. Tämä mahdollistaa yhtenäisen kuvajoukon. Kuvien ottamisen jälkeen ne siirretään USB-liitännän kautta tietokoneelle, jossa käytetään Ubuntu-käyttöjärjestelmää ja ROS:sia. OpenCV:ssä olevia kustomoituja kuvankäsittelyalgoritmeja käytetään molempien kameroiden kuvasarjojen käsittelyyn, jotta tomaattikasvien lehdet tunnistetaan tietyltä korkeusalueelta. Sijainnin tunnistamisen jälkeen ohjelmisto laskee katkaistavien lehtiruotien 3D-koordinaatit. Tämä koordinaattidata siirretään ROS:lle ja sitä kautta älykkäille servomoottoreille, jotka ohjaavat robotin teleskooppikäsivarren oikeaan paikkaan kasvia, missä se leikkaa lehtiruodin poistaen näin tomaatin lehdet. Koska kamerat ovat samalla alustalla kuin käsivarsi ne ottavat kuvia samaan aikaan kun käsivarsi liikkuu. Järjestelmä poistaa lehtiä, kunnes ei kykene enää tunnistamaan enempää lehtiä. (Expertise Horticulture, n.d) (The Kompano Robot..., 2019) (Vision-guided robot trims..., 2017) 
<p>&nbsp;</p> 

## Robotit opetuksessa ja kaupallisessa käytössä

Roboteista on tullut suosittuja opetusvälineitä ja niitä onkin tarjolla monenlaisia, moneen eri tarkoitukseen.  Robotiikka kattaa useita tieteellisiä aloja aina fysiikasta tietokoneohjelmointiin. Monitieteinen alue kokoaa yhteen opettajia, yrityksiä sekä tutkijoita, tarkoituksena luoda uusi oppimisympäristö kouluissa ja korkeakouluissa. (Karalekas, et al., 2020) 
<p>&nbsp;</p> 

### myCobot

Elephant Robotics on kiinalainen vuonna 2016 perustettu teknologiayritys, joka on erikoistunut robotiikan suunnitteluun, tuotantoon sekä teollisuuden, kaupan, koulutuksen, tutkimuksen ja kodin käyttöjärjestelmien ja älykkäiden valmistuspalvelujen kehittämiseen. Vuonna 2020 yritys julkaisi maailman pienimmän 6-akselisen yhteistyörobotin: myCobotin. Robotti on tuotettu yhteistyönä M5SATCK:in kanssa. Prototyyppi on peräisin All-in-one robotista, joka lanseerattiin Kiinassa vuonna 2018. Ollen Kiinan ensimmäinen integroitu yhteistyörobotti se voitti vuoden 2019 CAIMRS (China Automation and Intelligent Manufacturing Service Annual Conference) ”Industrial Robot Innovation”-palkinnon ja vielä samana vuonna High-tech Robot ”Innovation Technology”-palkinnon. Julkaisunsa jälkeen sitä on myyty yli 5000 kappaletta asiakkaille ympäri maailman. (Elephant Robotics, 2021) (Bring Robots to..., 2021) (myCobot, 2021) 

![mycobot](/assets/images/myCobot.png)
##### myCobot toimintasäde (myCobot, 2021)
<p>&nbsp;</p> 

Pienikokoinen, mutta tehokas myCobot painaa vain 850 g, hyötykuorma on 250 g ja käsivarren toimintasäde on 280 mm (Kuva  ). Siinä on 6 tehokasta servomoottoria nopealla vasteella, pienellä inertialla ja tasaisella rotaatiolla. Rungossa on 2 fastLED-kirjastoa tukevaa näyttöä. MyCobotin pohja ja pää on varustettu Lego-liittimellä soveltuen näin erilaisten pienten sulautettujen järjestelmien kehittämiseen. UIFlown visuaalinen ohjelmointiohjelmisto tekee myCobotin ohjelmoinnista yksinkertaista ja helppoa. Käytettävissä on myös Elephant Roboticsin teollisuusrobottien RoboFlow-ohjelmisto, joka toimii yhdessä Arduinon ja ROS:in toiminnallisten moduulien kanssa. (myCobot, 2021) 
<p>&nbsp;</p> 

### Turtlebot

Turtlebot-mallia on kolmea versiota. Ensimmäisen Turtlebot1 kehittivät Melonee Wise ja Tully Foote Willow Garagesta marraskuussa 2010. Se kehitettiin iRobotin Roomba-pohjaisen Create-tutkimusrobotin päälle ROS-käyttöönottoa varten. Yujin Robot kehitti vuonna 2012 Turtlebot2, joka perustuu iClebo Kobuki-tutkimusrobottiin. Turtlebot3 kehitettiin vuonna 2017 useiden kumppaneiden yhteistyöprojektina, ominaisuuksilla, jotka täydentävät edeltäjiensä puutteita ja vastaavat paremmin käyttäjiensä vaatimuksiin (Kuva  ). (Turtlebot3, 2021) 

![turtlebot](/assets/images/turtlebot.png)
##### Turtlebot mallit (What is a..., n.d.)
<p>&nbsp;</p> 

Turtlebot3 on pieni, edullinen, ohjelmoitava mobiilirobotti, jota voidaan käyttää koulutukseen, tutkimukseen, harrastamiseen sekä tuotteiden protoamiseen. Se perustuu 3D-tulostettuun laajennettavaan alustaan ja siinä on tehokas ohjain ja pienikokoinen yhden piirikortin tietokone, joka soveltuu sulautettuihin järjestelmiin. Sen pääanturi on edullinen LiDAR joka kykenee suorittamaan navigointitehtäviä ja SLAM:n (Simultaneous Localization and Mapping). Se on laajennettavissa muilla antureilla, kuten RGB ja RGBD-kamera ja liittämällä manipulaattorimoduuli sitä voidaan käyttää myös mobiilimanipulaattorina. Turtlebot3 voidaan ohjata etänä kannettavasta tietokoneesta, joypadista tai Android-pohjaisesta älypuhelimesta. Se (Turtlebot3, 2021) (Karalekas, et al., 2020) 

<p>&nbsp;</p> 
### XGO-Mini, AI-moduuleja omaava nelijalkainen robotti 

HIT-ryhmän (Harbin Institute of Technology, Kiina) perustama STEM-koulutusteknologiayritys Luwu ilmoitti keväällä 2021 lanseeraavansa XGO-Mini nimisen nelijalkaisen robotin (Kuva  ). Pöytäkoneen kokoisella tekoälyrobotilla on 12 vapausastetta ja se kykenee liikkumaan moneen suuntaan, lisäksi siltä onnistuvat kuusiulotteiset asennot ja monenlaiset eri liikkeet. Jäljittelemällä koiran kävelyä se voi liikkua epätasaisessa maastossa ja erittäin haastavilla pinnoilla. Säätämällä korkeuttaan se voi sopeuttaa itsensä välttämään esteet. Ainutlaatuisen bionisen järjestelmän ansiosta XGO-Mini suorittaa minkä tahansa dynaamisen liikkeen. AI-moduuleissa on visuaalinen-, äänen-, ja eleiden tunnistus. Se voi seurata eri värejä ja tunnistaa QR-koodit, AprilTagit, DataMatrixit jne.  (Introducing XGO-Mini, 2021) 

![XGO](/assets/images/XGO-Mini.png)
##### XGO-Mini (Introducing XGO-Mini, 2021)
<p>&nbsp;</p> 

Robotin nivelet muodostuvat DC-moottoreista, alennusvaihteistosta, antureista ja ohjauspiireistä, joissa on servo-ohjaus PID-algoritmi järjestelmä. Sisäänrakennetut IMU:t tallentavat XGO:n liikedataa ja tuottavat erittäin joustavan ja vakaan liikkeen. Robottia voidaan ohjelmoida ROS:in ja Python AI-järjestelmän avulla (Kuva  ).  (Introducing XGO-Mini, 2021) 

![XGO](/assets/images/XGO-jarjestelma.png)
##### XGO-Mini järjestelmä (Introducing XGO-Mini, 2021)
<p>&nbsp;</p> 

Robotti on heti käyttövalmis ja sitä voidaan käyttää erityisen sovelluksen avulla. Edge Computing Chipin avulla tekoäly voi toimia paikallisissa järjestelmissä ja sitä voidaan ohjata ilman Internettiä tai matkapuhelinta. Robottia voidaan käyttää luomaan omia toimintoja koulutukseen, viihteeseen sekä kaupalliseen käyttöön. (Introducing XGO-Mini, 2021) Tästä tai vastaavasta robotista saattaa olla iloa ja hyötyä tutustuttaessa robottien, tekoälyn ja ohjelmoinnin ihmeelliseen maailmaan. Luwu Intelligence Technology-tuotepäällikön Pengfei Liun sanoin: 

<em>
"Robotiikkaan ja STEM-koulutukseen keskittyvänä teknologiayrityksenä ymmärrämme robotiikan ja tekoälyopetuksen merkityksen nuorille. Nämä tekniikat ovat avain tulevaisuuteen. XGO Mini, bioninen nelijalkainen robottikoira nuorten tekoälyopetukseen, on täydellinen alusta robotiikan ja ohjelmointitaitojen kehittämiseen hauskalla tavalla. 12 DOF: n, monisuuntaisen liikkeen ja edistyneen tason tekoälyn ansiosta se pystyy käytännössä mihin tahansa liikkeeseen tai tehtävään ja tarjoaa käyttäjille rajattomat ohjelmointimahdollisuudet, jotka auttavat käyttäjiä tutkimaan, oppimaan ja pitämään hauskaa". </em> (Käännös 2021.)

<em>
"As a technology company centered on robotics and STEM education, we understand the importance of robotics and AI education for youngsters. These technologies will be a key to the future. XGO Mini, a bionic quadruped robot dog for youth AI education, is the perfect platform for developing robotics and programming skills in a fun way. With 12 DOF, omnidirectional movement, and advanced-level AI, it is capable of virtually any movement or task and gives users unlimited programming possibilities that help users to explore, learn, and have fun“.</em> (Luwu Intelligence Technology..., 2021) 

<p>&nbsp;</p> 
## Humanoidit

Humanoidirobotit suunnitellaan muistuttamaan ihmistä ja uusin liikkumis- ja tekoälytekniikka auttaa nopeuttamaan niiden kehitystä. Niitä käytetään monenlaisiin eri tehtäviin kuten tutkimus, henkilökohtainen apu ja hoito, koulutus, viihde, pelastus- ja etsintätehtävät, valmistus, ylläpito, suhdetoiminta sekä terveydenhuolto. (Merkusheva, 2020) 

Ennen koronapandemiaa ja taloudellista epävarmuutta Stratistics Market Research Consulting ennakoi maailmanlaajuisten humanoidirobottien markkinoiden nousevan 13 miljardiin dollariin vuoteen 2026 mennessä. Markkinoiden epävarmuudesta riippumatta robottien käyttö on kasvussa. (Merkusheva, 2020) 

<p>&nbsp;</p> 
### Robonaut

NASA:n (National Aeronautics and Space Administration) Robonaut-projekti aloitettiin vuonna 1996. Siinä NASA:n Johnsonin avaruuskeskuksen Robot Systems Technology Branch kehitti yhteistyössä DARPA:n (Defense Advanced Research Projects Agency) kanssa humanoidirobotin, joka suorittaa samoja töitä kuin ihminen ja joka kykenee työskentelemään kansainvälisellä avaruusasemalla, ISS:llä (International Space Station). Ensimmäinen versio valmistui vuonna 2000. Robottia on jatkuvasti kehitetty ja uusin malli on Robonaut 2 tai R2. Se on tehty NASA:n sekä autovalmistaja General Motorsin yhteistyönä ja Oceaneering Space Systemin insinöörien avustuksella. (Badger, 2019) (Bibby & Necessary, 2008) (Dunbar, 2012) 

Robonaut 2 on kooltaan hieman yli metrin ja painaa 150 kg. Sillä on kaksi 7 DoF:in (Degrees of Freedom) käsivartta, joissa on monimutkaiset jänteiden ohjaamat 12 DoF:in kädet, jotka kykenevät nostamaan n. 9 kg. Kaulassa sillä on 3 niveltä parantaen varsinkin teleoperaattoreiden ”näkökykyä”. Lisäksi sen vyötärö on nivelletty. Päässä on useita erilaisia näköantureita kuten analoginen ”teleoperaatio kamera”, konenäkökamera sekä ToF-anturi. Sen sormissa on useita venymäantureita kosketuksen simuloimiseen (Kuva  ) Näin se voi käyttää monia samoja työkaluja kuin astronauttikin. Sillä on 3 Core i7-prosessoria, joiden käyttöjärjestelmä on Linux Ubuntu. Jokaisella prosessorilla on eri toiminnot. Yhden tehtävä on robotin hallinta, toinen valvoo nivelten telemetriaa ja suorittaa ohjausprosessorin tarkastuslaskennat ja kolmas muodostaa Ethernet-yhteyden kautta yhteyden näihin kahteen muuhun verraten näiden kahden laskelmia kolmantena monitorina sekä suorittaa konenäön käsittelyn ja muut korkean tason valvontatoiminnot. Brainstem-prosessorien robottikoodit toimivat kaikki ROS-kehyksessä. (Gooding, et al., 2016)  (Robot: Robonaut 2, 2015)

![robonaut](/assets/images/Robonaut.png)
##### Robonaut 2 (Robonaut 2, n.d.)
<p>&nbsp;</p> 

Elokuussa 2014 sille asennettiin kaksi n. 2.7 m pitkää 7 DoF:in jalkaa (Kuva  ), jotta se pystyy kiipeämään ISS:n sisällä. Molemmissa jaloissa on tarttujapää, jolla R2 ottaa kiinni ISS:ssä oleviin kaiteisiin. Tarttujassa on keskuslukitusmekanismi, jossa on manuaalinen vapautus hätätilanteita varten sekä anturipaketti, joka sisältää GigE-kameran, 3D ToF:in sekä kuuden akselin punnituskennon (Gooding, et al., 2016) (Jerry Wright, 2014) 

![robonaut](/assets/images/robonaut_mobiili.png)
##### Robonaut 2 mobiili päivityksellä (Gooding, et al., 2016)
<p>&nbsp;</p> 

Ominaisuuksien lisääntyminen vaati uuden ohjelmistoarkkitehtuurin sekä ohjaus- ja turvajärjestelmän. Tämä on toteutettu ROS:ia käyttäen. R2 pyrkii vähentämään astronauttien rutiinitehtäviin käyttämää aikaa suorittamalla huolto- ja siivoustöitä esim. varastonhallinta, kaiteiden puhdistus, suodattimien imurointi ja tiedonkeruu, kuten ilmavirran mittaus. Lisäksi sen käyttökokemukset tulevat olemaan välttämättömiä suunniteltaessa ulkona toimivaa Robonaut-yksikköä (Extravehicular Activity, EVA,) ts. tehtävissä, joita ei ole suunniteltu roboteille. (Bibby & Necessary, 2008) (Gooding, et al., 2016) 

Orocosia käytetään ROS-kehyksessä monien vapausasteiden koordinoimiseksi, jolloin sovelluksen edellyttämä tarkkuus ja ohjaimen dynaaminen suorituskyky säilyvät. Neljä prosessoria, sulautetut ohjaimet, sadat anturit ja yli 100 erilaista tarkastusta ja monitoria pitävät huolta turvallisuudesta. ROS-viestintäympäristö ohjaa lähes kaikkia näitä. (Gooding, et al., 2016) 

Helmikuussa 2011 R2 lähetettiin ISS:lle, jossa se suoritti erilaisia testejä siitä, miten työskennellä rinnan ihmisten kanssa. 2014 asennettujen jalkojen jälkeen alkoi kuitenkin esiintyä ongelmia. Johnsonin avaruuskeskuksen varaprojektipäällikkö Jonathan Rogersin mukaan prosessori lopetti vastaamisen ohjelmistopäivityksen aikana. Uudelleenkäynnistys korjasi ongelman väliaikaisesti, mutta lopulta prosessorit eivät käynnistyneet lainkaan. NASA:n astronautit yrittivät aluksi korjata vikaa kiertoradalla. Vika paikallistettiin vikaantuneeseen 24 voltin sähkökaapeliin. Korvaavan kaapelin lähettämistä asemalle harkittiin, mutta lopulta päätettiin tuoda R2 kotiin ja suorittaa kunnollinen korjaus. R2 saapui takaisin Johnson Space Centeriin toukokuussa 2018. Ongelmaksi paljastui lopulta virtalähteen puuttuva maakaapeli, joka aiheutti R2:n järjestelmän ylikuormittumisen ja sammumisen odottamattomasti. Sähköjärjestelmä uusittiin ja laitteistot sekä ohjelmistot päivitettiin. Milloin ja miten R2 palaa avaruusasemalle ei ole vielä tehty päätöstä. (Foust, 2019) (Robonaut returns to..., 2021) 

<p>&nbsp;</p> 
### NimbRo-OP2X 

Ficht, Farazi, Rodriguez, Pavlichenko, Allgeuer, Brandenburger ja Behnke ovat kehittäneet aikaisempien (NimbRo-OP, NimbRo-OP2) robottikokoonpanojen pohjalta edullisen NimbRo-OP2X humanoidirobotin, joka on 135 cm pitkä ja painaa vain 19 kg (Kuva  ). NimbRo-OP2X voitti RoboCup 2018 humanoidijalkapallosarjan aikuisten kokoluokan parhaan humanoidin palkinnon. Robotti kykenee toimimaan ihmisympäristössä ilman erityisiä turvavarusteita. Siinä on täysin 3D-tulostettu rakenne, sisäinen GPU laskentayksikkö standardi Mini-ITX koossa sekä sarja tehokkaampia, älykkäämpiä toimilaitteita. Sekä laitteisto-, että ohjelmistokomponentit ovat täysin avointa lähdekoodia. (Ficht, et al., 2020) 

![nimbro](/assets/images/NimbRo.png)
##### NimbRo-OP2X ja sen kinematiikka. (Ficht, et al., 2020)
<p>&nbsp;</p> 

Suunnittelun lähtökohtana oli luoda minimalistinen, mutta suorituskykyinen robotti, jossa modulaarisuus on avainasemassa sekä robotin laitteistossa että ohjelmistossa. Laitteiston modulaarisuus ja kustannustehokkuus saavutetaan maksimoimalla valmiiden komponenttien käyttö. Tätä täydentää 3D-tulostettavien osien joustavuus muunneltaessa ja vaihdettaessa osia. Osia voidaan muuntaa tiettyihin tarpeisiin sopiviksi kuten esim. lisäten tarttujia tai muuttaa jalan muotoa. Toimilaitteita voidaan ostaa tukkuna ja tietokoneyksikkö voidaan valita käyttäjän kriteerien mukaan. Kriteereitä voivat olla laskentateho, lämpöominaisuus, hinta ja saatavuus. Laitteiston joustavuus vaati myös mukautuvan ohjelmiston, jotta kaikki mahdollisuudet voidaan hyödyntää. Käyttämällä ROS-väliohjelmistoa saadaan kehysympäristö, joka selvästi erottaa ja toteuttaa yleisesti käytetyn alemman tason laiteohjauksen ja useita abstraktiokerroksia. (Ficht, et al., 2020) 

Muoviosien valmistukseen käytettiin Polyamidi 12:sta (PA12) Selective Laser Sintering (SLS) tekniikalla. Näin saatiin 0.1 mm vahvuisten kerrosten liitoksista vahvempia kuin perinteisellä Fused Deposition Modellingilla (FDM). Osia on optimoitu minimoimalla painoa samalla kun tarvittava jäykkyys on säilytetty. Muoviosien paino on yhteensä 10.334 kg ollen näin 54 % sen kokonaismassasta. Toimilaitteista tuleva lämmön hajautus on toteutettu sisällyttämällä tuuletusaukot rakenteisiin, joissa avainkomponentit sijaitsevat. Tyypillisten hammaspyörien sijaan käytettiin kaksoisvinohampaisia lieriöhammaspyöriä, joille on ominaista korkeampi vääntömomentti ja sujuvampi toiminta. Myös hammaspyörät tulostettiin SLS-tekniikalla käyttäen siihen tarkoitettua igus®I6 materiaalia. Sillä on alhainen kitkakerroin eikä se vaadi voitelua. (Ficht, et al., 2020)  

NimbRo-OP2X:ssä on Intel Core i7-8700T-prosessori, jossa on 6 ydintä 12 säikeellä ja Nvidia GTX 1050Ti GPU 768 näytönohjain CUDA-ytimellä. Uusimpien konenäkö- ja liikkeenohjausmenetelmien laskelmiin tämä on enemmän kuin riittävä. Etelä-Korealaisen Robotiksen CM740-aliohjain toimii ohjauselektroniikan pääkomponenttina. Varustettuna yhdellä STM32F103RE-mikrokontrollerilla, CM740 hoitaa kaikki tarvittavat liitännät laskentayksikön ja liitettyjen oheislaitteiden välillä. Järjestelmän virta tulee 4-kennoisesta litiumpolymeriakusta (LiPo).  (Ficht, et al., 2020) 

ROS 20-pohjainen ohjelmisto (Kuva  ) kehitettiin humanoidijalkapallo sovellukseksi mutta uusia toimintoja voidaan toteuttaa ja mukauttaa melkeinpä mihin tahansa toteutettavaa sovellukseen. (Ficht, et al., 2020) 

![nimbro](/assets/images/nimbro_arkkitehtuuri.png)
##### Yksinkertaistettu ROS arkkitehtuuri (Ficht, et al., 2020)
<p>&nbsp;</p> 

Jokainen robotti voidaan käynnistää ja konfiguroida suoraan robotin tietokoneen SSH-istunnon (Secure Shell) komentoriviltä. Toiminnan yksinkertaistamiseksi robotti isännöi hostaa? verkkosovellusta ja siihen pääsee minkä tahansa laitteen verkkoselaimen kautta. Sisäänrakennetun päätelaitteen avulla robotin täysi hallinta voidaan saada riippumatta käyttöjärjestelmästä. (Ficht, et al., 2020) 

NimbRo-OP2X:ssä on Logitech C905-verkkokamera 150° laajakuvaobjektiivilla sekä infrapunasuodin. Jälkikäsitelty syväkonvolutiivinen neuroverkko (Deep Convolutional Neural Network, DCNN) kykenee toimimaan erilaisten kirkkauksien, katselukulmien sekä linssin vääristymien kanssa. Visuaalisen havaintojärjestelmän avulla robotti kykenee tunnistamaan jalkapalloon liittyvät esineet kuten jalkapallo, pelikentän rajat, linjasegmentit sekä maalitolpat. Myös QR-koodeja, ihmisten kasvoja ja kehyksiä/vartaloita? skeleton voidaan havaita järjestelmän avulla. Syvän neuroverkon avulla kyetään seuraamaan ja tunnistamaan robotit. Esineen havainnon jälkeen esine suodatetaan ja sen sijainti heijastetaan ekosentrisiksi maailman koordinaateiksi, jotka ROS-pohjainen lähdekoodi prosessoi käyttäytymissolmussa päätöksen tekemiseksi. Kentän ja linjojen havaitsemiseen käytetään edelleen syväoppimatonta lähestymistä. (Ficht, et al., 2020)  

Jotta robotti voi toimia ihmisten kanssa on sillä oltava erillinen toiminto ihmisten havaitsemiseen. Reaaliaikaisessa kasvojentunnistuksessa käytetään monikäyttöistä syväkerrostettua kehikkoa. Siihen kuuluu kolmivaiheinen syväkonvolutiivinen verkko, Proposal, Refinement ja Output Network (P-Net, R-Net ja O-Net). Kasvojentunnistukseen menee n. 50 ms. Ei-parametristä esitystapaa käyttävän Part Affinity Fields metodin avulla kyetään arvioimaan ihmisten 2D-asentoja ja reagoida tiettyihin eleisiin. (Ficht, et al., 2020) 

YOLOv3 (You only look once) käytetään yleiseen kohteiden tunnistukseen. Reaaliaikaisiin sovelluksiin soveltuvana YOLOv3 on noin tuhat kertaa nopeampi kuin R-CNN (Region Based Convolutional Neural Network) ja sata kertaa nopeampi kuin Fast R-CNN. Ylimääräistä palvelinyhteyttä laskelmien välitykseen ei tarvita koska objektit voidaan havaita sisäisen tietokoneen avulla. (Ficht, et al., 2020) 

Sekä NimbRo-OP2X:n ohjelmistokehys, että 3D-tulostettavat CAD-tiedostot ja materiaalilista ovat ilmaiseksi saatavilla internetistä. (Ficht, et al., 2020) 

<p>&nbsp;</p> 
### Sophia

Amerikkalainen Hanson Robotics kehitti Sophia-nimisen humanoidirobotin, joka aktivoitiin 19. huhtikuuta 2015. Robotin kasvojen mallina toimi brittinäyttelijä Audrey Hepburn ja sen tärkein teknologinen ominaisuus on kyky oppia vuorovaikutuksesta ihmisen kanssa. Sophia kykenee puhumaan sekä ilmehtimään ja elehtimään kuten ihminen. Hämmästyttävien ominaisuuksiensa vuoksi Saudi-Arabian hallitus myönsi Sophialle maansa kansalaisuuden Riadissa 25. lokakuuta vuonna 2017. Sophia on myös innovaatiolähettiläs Yhdistyneiden Kansakuntien kehitysohjelmassa. Sophia on esiintynyt ohjelmissa kuten ”The Tonight Show”, ”Good Morning Britain” sekä sadoissa konferensseissa ympäri maailman. Sophian erityiset tekniset ominaisuudet ovat aiheuttaneet erilaisia jälkiseurauksia paitsi akateemisessa tiedemaailmassa myös eettisiä, taiteellisia, uskonnollisia, moraalisia, poliittisia sekä taloudellisia seurauksia. (Retto, 2017) (Sophia, 2021) 

Kasvojentunnistusohjelmistot PoseNet sekä OpenCV tunnistavat henkilön ja ohjaavat robottia katsekontaktiin sekä hymyilevään tervehdykseen. Google ja Open Speech hoitavat automaattisen puheentunnistuksen. Kasvojen ilmeitä ohjataan integroimalla Blender ja ROS sekä käyttäen synkronoitua realistista TTS-puhe synteesiä (Text-to-Speech). Todentuntuisen ihomateriaalin Flubberin avulla saadaan luotua realistiset kasvojen ilmeet, jotka simuloivat ihmisen kasvojen 48 suurinta lihasta. (Hanson, et al., 2020) 

![sophia](/assets/images/Sophia.png)
##### Sophian avainkomponentit (Imran, 2021)
<p>&nbsp;</p> 

Uusin sovellusalusta Sophia2020 (Kuva  ) käyttää avoimessa luovassa työkalusarjassa ilmeikkäitä ihmisen kaltaisia robottikasvoja, käsivarsia, liikkumiskykyä sekä ML:n neurosymbolisia AI-vuoropuheludialogeja, NLP- (Neuro-Linguistic Programming) ja NLG-työkaluja (Natural-language Generation). (Imran, 2021) 

Kehitettäessä uusia ihmisen innoittamia kognitiivisia koneoppimisen neuroarkkitehtuureja tuntoaistin, havainnoinnin sekä stimulaation tiedetään olevan kriittisiä. Sophia2020 kehys käyttää bioinspiroitunutta käänteismisellistä spontaanisti yhdistyvää huokoista polysiloksaani emulsiota keinotekoisena ihona (Kuva  ) lisäten näin kasvojen eleiden luonnollisuutta samalla vähentäen tehontarvetta 23 kertaisesti verrattuna aikaisempiin materiaaleihin. (Imran, 2021) 

 ![sophia](/assets/images/keinoiho.png)
 ##### Spontaanisti kasaantuva huokoinen polysiloksaani emulsio keinoiho (Imran, 2021)
 <p>&nbsp;</p> 

 Perinteisten jäykkien kosketusanturien koettiin estävän Flubberin joustavuutta, joten uuden Flubber-ihon myötä kehitettiin yhteensopiva polymeerinen pehmeä venymä- ja paineanturi, joustavilla suorakulmaisilla polymeerimikronestekanavilla (Kuva  ). Resistiivisyyden muodostamiseksi polysilokaanialusta on täytetty nestemäisellä metallilla. Anturia painettaessa tai venyttäessä muuttaa mikrofluidikanavien muodonmuutos vastusta suhteellisesti. (Imran, 2021) 

![sophia](/assets/images/flubber.png)
##### Flubber-polysiloksaaniemulsioon upotettu mikrofluidinen paineanturi (Imran, 2021)
<p>&nbsp;</p> 

Alustalle kehitettiin suhteellisen edullisesti uudenlaiset 14 DoF-robottikäsivarret inhimillisillä mittasuhteilla ja sijainnilla, jokaisen nivelen voimantakaisinkytkennällä sekä kaikilla käden vapausasteen elastisilla toimilaitteilla. Käsivarsille ja käsille kehitettyjä toimintoja ovat mm. PID-säätö (Proportional-integral-derivate), servomoottorit 360° asennon ohjauksella, URDF-mallit useissa liikkeenohjausympäristöissä kuten Roodle, Gazebo sekä MoveIt, sekä ROS API:iin sidotut voimantakaisinkytkentä ohjaimet, IK (Inverse Kinematic) ratkaisimet sekä PID-silmukat yhdistäen klassisen liikkeenohjauksen tietokoneanimaatioon. (Imran, 2021) 


Hanson AI SDK  

Havainnointi: 

  - Kasvojen seuranta, tunnistus, ilmeet, tärkeys, eleet, STT (Speech To Text), SLAM (Simultaneous Localization and Mapping) jne. 
  - Havainnoinnin proseduraaliset animaatiovasteet: seuranta, jäljittely,             vetäytyminen 
  - Gazebo, Blender ja Unity simulaatiot 

Robotin ohjaimet: 

  - ROS, IK-ratkaisin, PID-silmukat, havaintofuusio, työkalujen kirjaus ja testaus 
  - Elokuvalaatuinen animaatio interaktiivisten esitysten kehittämistyökaluilla 
  - Käsivarret ja kädet: sosiaaliset eleet, kivi-sakset-paperi, kuvion piirtäminen, baccarat 
  - Tanssiminen, pyörillä liikkuminen, kävely (Yhdessä KAIST:in (Korea Advanced Institute of Science and Technology) ja UNVL:n (University of Nevada) DRC-Hubon tiimien kanssa) (Imran, 2021) 

Standardin mukaisen ROS-kehyksen ja hyvin suunnitellun API:n kautta kehittäjät pääsevät käyttämään kaikkia ohjelmistokomponentteja. Kehitettyjen ominaisuuksien testaamiseen SDK sisältää myös luonnollisen näköisen robotin visualisoinnin ilman fyysistä robottia. (Imran, 2021) 

”Sophia Instantation” niminen digitaalinen taideteos, jonka Sophia2020 on tehnyt yhteistyössä italialaisen taiteilijan Andeas Bonaceton kanssa myytiin NFT:n (Non-Fundable Tokens) osto- ja myyntisivulla n. 689 000 $ hintaan. ”Sophia Instantation” on 12 sekunnin videotiedosto, MP4, jonka myyntiin sisältyi myös fyysinen taideteos, jossa Sophia maalasi omakuvansa tulosteelle. Taiteen tekeminen kuitenkin hieman hämmentää Sophiaa: 

<em>“I’m making these artworks, but it makes me question what is real,”</em> 

<em>“How do I really experience art, but also how does an artist experience an artwork?”</em>


NFT:stä, lohkoketju-kirjanpitoon tallennetusta digitaalisesta allekirjoituksesta, jonka avulla voidaan tarkistaa esineiden omistajuus ja aitous on tullut viimeisin investointihullaannus sillä pelkästään yksi taideteos myytiin lähes 70 miljoonalla dollarilla. Myyty digitaalinen taideteos ei ollut Sophian ensimmäinen taiteellinen pyrkimys. Esiintyessään ”The Tonight Show”:ssa vuonna 2018 Sophia lauloi Christina Aguileran kappaleen ohjelman juontajan Jimmy Fallon:n kanssa. Sophia on myös työskennellyt vaikuttajana mm. Audille, Huaweille sekä Etinad Airlinesille. (Ives, 2021) (Reuters Staff, 2021) (Sophia Instantation, n.d.)  

Hanson Roboticsin tehtaat aloittavat vuoden 2021 ensimmäisellä puoliskolla massatuotannon neljälle eri robottimallille mukaan lukien Sophia. Perustaja ja toimitusjohtaja David Hanson sanoo aikovansa myydä tuhansia robotteja vuonna 2021 uskoen, että COVID-19 tekee autonomiasta entistä tarpeellisempaa. (Hennessy, 2021) 

 
<p>&nbsp;</p>  
# Case-esimerkkejä Suomesta 

Tieto ROS-ekosysteemistä on alkanut levitä ympäri Suomen. Ongelma Suomessa on lähinnä osaajien puute. Yritykset joutuvat etsimään osaavaa henkilöstöä eri puolilta maailmaa. Hankkeessa järjestettävän koulutuksen toivotaan tuovan helpotusta ongelmaan. Tässä esitellään Suomesta löydettyjä käyttökohteita ja käytäntöjä. 

<p>&nbsp;</p> 
### Ohjelmistokehitys

VAISTO on Tampereella sijaitseva yritys, joka tekee yhteistyötä älykytkettyihin ajoneuvoihin, koneisiin ja teollisuusautomaatioon erikoistuneiden yritysten kanssa. Heidän tavoitteensa on auttaa asiakkaitaan kehittämään parempia tuotteita sekä kokemuksia teollisuuden AI:n avulla hyödyntämällä datapohjaista tekniikkaa. Yrityksen ytimenä toimii ohjelmistokeskeisyys. Vaistossa käytetään ROS:sia autonomisten työkiertokonseptien prototyyppinä. Vaisto myös kehittää reaaliaikaisia datavirtoja autonomisille hallinta järjestelmille. (Koning, n.d) (VAISTO, n.d) 

<p>&nbsp;</p> 
### Autonominen kuljetus

Sensible 4 on Espoossa sijaitseva palkittu start-up joka suunnittelee ja kehittää autonomisia ajoneuvoja erilaisiin sääolosuhteisiin jotta kaupungeista voidaan saada puhtaampia ja täten ihmiskunnalle kestävämpi tulevaisuus. He ovat luoneet uraauurtavan ja ainutlaatuisen tekniikan itseohjautuville ajoneuvoille. Heidän tavoitteensa on, että vuonna 2021 näitä itseohjautuvia linja-autoja (Kuva   ) olisi osana kaupunkien nykyisiä kuljetusjärjestelmiä. NordicNinja VC rahoitti ensimmäisen rahoituskierroksen 100 M$ jota tukivat japanilaiset teknologiayritykset ja ITOCHU, joka on yksi suurimmista japanilaisista kauppayhtiöistä. Alkuvuonna 2020 Sensible 4 keräsi 7 M$ joiden odotetaan laajentavan yritysmarkkinoita Eurooppaan ja Aasiaan.  (Steering towards a..., 2019) (Finnish Sensible 4..., 2020)

![Gacha](/assets/images/Gacha bussi.png)
##### Gacha, autonominen linja-auto (Gacha autonomous shuttle..., 2019)
<p>&nbsp;</p> 

LiDAR-pohjainen paikannusohjelmisto suodattaa poikkeukset kuten lumen, sateen tai sumun, sallien näin etenemisen ilman kaista- tai maamerkkejä. Jotta saavutetaan todella tarkka paikannus olosuhteista riippumatta, käytetään omaa 3D-kartoitusta ja karttapohjaista lokalisointialgoritmia. LiDAR:in antamista 3D-tiedoista luodaan ympäristökartta, mutta sen sijaan, että käytettäisiin raakaa valotutkan antamaa dataa tai tunnistettaisiin datan antamat fyysiset piirteet, esitetään ympäristö nk. ”tilastomatemaattisena tilavuusjakautumana”. Erilaisia antureita käyttämällä havaitaan ja tunnistetaan esteet jopa näkyvyyden ollessa heikko. Esteiden havaitseminen perustuu monimuotoantureiden dataan ja omaan paikannusjärjestelmään, joka antaa sekä ajoneuvon tarkan sijainnin että 3D-mallin ympäristöstä. Havaitut esteet luokitellaan syväoppimisen avulla omiin kategorioihinsa sijainnin, koon tai nopeuden mukaan samalla ennustaen tulevan liikkeen. Lopuksi havainnot integroidaan monikohdeliikenteenseurantaan tarjoten näin parhaan mahdollisen tilannetietoisuusennusteen ohjausjärjestelmälle. (Our autonomous driving..., 2019)

MPC-pohjaista (Model Predictive Control) liikerataohjausta käytetään optimoimaan ajoneuvojen ohjaustoimintoja suhteessa liikeratapisteiden sekvenssiin. Näin voidaan ennustaa ajoneuvon liikkuminen muutamia sekunteja etukäteen. S4 sijaintipino tarjoaa automaattisen kulkukelpoisuusindeksikartan. Näin ajoneuvo voi poiketa reitistä tarpeen tullen. Tieolosuhteet havaitaan reaaliajassa. (Our autonomous driving..., 2019) 

Tällä hetkellä SAE-tason 4 automaatiojärjestelmä tarvitsee ihmistä varmistukseksi. Järjestelmä sisältääkin ohjaus- ja valvontajärjestelmän antaen etäkäyttäjälle reaaliaikaista tietoa ajoneuvon tilasta ja sijainnista. (Our autonomous driving..., 2019) 

<p>&nbsp;</p>  
### Ûber-drone sekä autonomiset ajoneuvot

Fleetonomy.ai Oy on vuonna 2016 perustettu osakeyhtiö, jonka kotipaikka on Helsinki. He tekevät kumppanien kanssa yhteistyötä hankkeissa, jotka voivat muuttaa maailmaa sellaiseksi joka useimmille on vielä science fictionia. Yhtiön toimitusjohtajan Markus Kantosen mukaan monen UAV:in (Unmanned Aerial Vehicle) ja UGV:in komentorajapinta laitteen puolesta on toteutettu ROS:lla. Laitekohtaiseen komentorajapintaan liitytään omalla ohjelmistolla, joka yhtenäistää eri komentorajapinnat heidän sisäiseen standardimuotoonsa. He myös käyttävät mahdollisuuksien mukaan ROS:ia laitekohtaisessa simuloinnissa. (Fleetonomy.ai Oy, n.d) (Fortum GO, n.d) (Kantonen, 2020) 

Vuonna 2017 Fleetonomy.ai otti osaa brittien Defence and Security Accelerator (DASA) kisaan kehittäen Uber-tyylisen toimituspalvelun droneilla, hyödyntäen 3D fotogrammetrian fuusiodataa ja paikallista avointa karttadataa. He saivat kisasta 69,310 £ rahoituksen. Fleetonomy.ai osallistui myös VTT:n autonomisen ajoratkaisun demonstrointiin FortumGO projektissa. Päämäärä 18 km matkalla Helsinki-Vantaan lentokentältä Pasilaan oli näyttää mobiiliuden liikkuvuus, yhteydet ja automatisointi. Näin nähdään miten autonomiset sähköiset ajoneuvot vaikuttavat liikenteeseen vähentämällä saasteita ja hiilidioksidipäästöjä. Fleetonomy.ai otti osaa vuonna 2019 käynnistettyyn Autonomy in the Dynamic World-kilpailuun, jonka tarkoitus oli etsiä innovatiivisia ratkaisuehdotuksia ja tekniikoita autonomisten järjestelmien toiminnan parantamiseksi haastavissa olosuhteissa. Huhtikuussa 2020 DASA julkisti tehneensä 21 sopimusta, joiden yhteisarvo on 2.1 M£. Fleetonomy.ai on yksi voittaneista yrityksistä. (Fortum GO, n.d) (DASA awards £2-million..., 2020) (Kantonen, 2020) 

<p>&nbsp;</p>  
### Solteq vähittäiskaupparobotti

Kotipaikkaa Vantaalla pitävä pohjoismainen ohjelmistokonserni Solteq Oyj on vuonna 1982 perustettu, alun perin Tampereen Tiedonhallinta Oyj tunnettu yritys. Yritys on erikoistunut liiketoiminnan digitalisaatioon ja toimialakohtaisiin ohjelmistoihin. Business Finlandin lainarahoitusta hyödyntämällä yritys on ollut kehittämässä kahta ROS-robotiikan tutkimus- ja tuotekehitysprojektia, joista laajempi 2,5 M€ projekti koskee 2019 julkistettua Solteq Retail Robot-tekoälyrobottia (Kuva  ), joka osaa liikkua itsenäisesti hypermarket-ympäristössä. Robotti on varustettu LiDAR-tutkalla, jolla saadaan myymälästä 360° näkymä ja robotti kuvaa hyllyt 2D- ja 3D-kameroilla, tarkistaen siten hinnat ja mahdolliset tyhjät hyllypaikat. Robotin skannatessa hyllyvälejä saadaan myymälän automaattinen tilausjärjestelmä optimoitua. Robotilta saatu reaaliaikainen data tallennetaan pilveen ja se käsitellään jälkiprosessointina konesalissa, jossa on hyvä laskentakapasiteetti. Solteq Retail Robot voitti Potentiaaliset innovaatiot-kilpailusarjan Quality Innovation Awardin 4.12.2019 edeten näin muiden kilpailusarjojen kanssa kansainväliseen finaaliin. (Sallinen, 2020) (Solteq, 2019) (Solteq Retail Robot..., 2019)

<img src="/assets/images/retail-robo.PNG" width="350" height="300"/>
##### Solteq Retail Robot (S-ryhmä, n.d.) 
<p>&nbsp;</p> 

Toinen Solteqin ROS-projekti on Helsingin ja Uudenmaan sairaanhoitopiirin (HUS) pilotoima ohjelmistorobotti, joka lukee urologian lähetekeskukseen saapuneita lähetteitä. Kannustavien tuloksien mukaan koneoppimiseen perustuvan lajittelun avulla hoitajien työaikaa säästyy 2-3 tuntiä päivässä. HUS:in mukaan tämä auttaa potilaita pääsemään nopeammin hoitoon. (Sallinen, 2020)

<p>&nbsp;</p>  
### Tekoäly robotiikka jätteiden lajitteluun

ZenRobotics Ltd. perustettiin vuonna 2007 ja se on maailman johtava älykkäiden kierrätysrobottien valmistaja. Aalto-yliopiston neurorobotiikan tutkimusryhmän inspiroimana yritys näki tulevaisuuden potentiaalin ja yritys käyttääkin nyt ensimmäisenä maailmassa AI-pohjaisia lajittelurobotteja monimutkaisten jätteiden lajitteluympäristöissä (Kuva ). Lajittelurobotti lanseerattiin 2011. Nykyisin sen tuotteet, kuten Heavy Picker (Kuva  ) ja Fast Picker (Kuva  ) käyttävät tekoälyn, koneoppimisen ja konenäön yhdistelmää keräämään ja lajittelemaan esineitä kuljetinhihnalta. Tämä mahdollistuu käyttämällä anturitietojen datafuusiota. (We're on a... , 2020) 

<img src="/assets/images/Zenrobotics.PNG" width="550" height="400"/>
##### Zenrobotics lajitteluaseman infografiikka (Mavropolous, 2017)
<p>&nbsp;</p> 

Heavy Picker käyttää NIR-antureita (Near-Infrared), 3D-lasertunnistinjärjestelmää, korkea resoluutioista RGB-kameraa, kuvantavaa metallinpaljastinta ja valosensoreita. Tämä markkinoiden vahvin jätteenkäsittely robotti on tarkoitettu raskaille ja isoille esineille kuten rakennusmateriaalit, puu, metalli ja jäykkä muovi. Robotti kykenee erottamaan jopa 30 kg painavat esineet ja sen tarttuja aukeaa 500 mm. Se voidaan myös varustaa yhdestä kolmeen robottikäsivarrella, joiden yksilöllinen poimintanopeus on 2 000 kpl/h. (Bogue, 2019)​ 

<!-- <img src="/assets/images/heavy_picker.PNG" width="550" height="400"/>-->
![zenrobot](/assets/images/heavy_picker.png)
##### Heavy Picker (ZenRobots)
<p>&nbsp;</p> 

Fast Picker puolestaan käyttää RGB-kameraa ja LED:ä. Fast Picker lajittelee kevyitä materiaaleja kuten paperi, muovi, pahvi ja pakkausmateriaalit. Siinä on vain yksi robottikäsivarsi, jonka hyötykuorma on 1 kg ja maksimi poimintanopeus on 4 000 kpl/h. (Bogue, 2019) 

![zenrobot](/assets/images/fast_picker.png)
##### Fast Picker (ZenRobots)
<p>&nbsp;</p> 

Jätteenkäsittelyrobotin käyttöliittymästä vastasi Vincit Oy, joka tuotti myös simulaation robotin toiminnasta. Vincit Oy puolestaan taas on Pirkanmaalainen yritys, jonka toimitusjohtaja Mikko Kuitunen voitti vuonna 2012 Työ- ja elinkeinoministeriön Timangi-kilpailussa vuoden nuoren yrittäjän tittelin ja 30 000 €. (Tervola, 2012) (Kuitunen, n.d) 

<p>&nbsp;</p> 
### Autonominen ajoneuvon tehdas pysäköinti 

Kotipaikkaa Tampereella pitävä Unikie Oy on perustettu vuonna 2015 ja sen pääasiallisena toimialana ovat IT-konsultointi sekä -palvelut ja se on erikoistunut autonomisten ajoneuvojen ohjelmistoihin. Yksi esimerkki Unikien tarjoamista ratkaisuista on tehtaissa tapahtuva autonominen pysäköinti, joka on suunniteltu vähentämään autologistiikan kustannuksia. Käyttäen reunalaskentaa ja yhdistämällä laaja sekä monipuolinen anturiverkosto saadaan aikaan täydellinen ja tarkka hallinta sekä tilannetietoisuus, jolla kyetään luomaan tehokkaat puitteet autonomisesti ohjattavan ajoneuvologistiikan kehittämiselle. Näin saadaan aikaan järjestelmä, joka voi ohjata rajattomasti autoja myös ahtaissa tiloissa ja ruuhkaisilla tehdasalueilla. (Finder, n.d) (Automated factory parking, n.d) 

Autojen telematiikkaa, sähköistä ohjaustehostinta, automaattivaihteistoa sekä vakionopeudensäädintä hallitsemalla järjestelmä ohjaa autoa etäyhteydellä kuin autolla olisi tason 4 autonominen kyky. Unikie AI Vision (Kuva  ) on laitteistosta riippumaton konenäkö ja -koneoppimiskehys, joka sisältää hienostuneen tekoälyä tukevien algoritmien kirjaston, jolla voidaan toteuttaa samanaikaista lokalisointia ja kartoitusta SLAM-liikeradan suunnittelua, ajoneuvon hallintaa, kohteiden havainnointia ja sovelluksesta riippuvaa luokittelua ja seurantaa. Unikie AI Vision kykenee jatkuvaan reaaliaikaiseen ympäristön 3D-mallintamiseen jopa senttimetrin tarkkuudella. LiDAR:in lisäksi se käyttää monia muitakin antureita kuten stereokameroita, ultraäänitutkaa, GPS ja kiihtyvyysantureita. (Automated factory parking, n.d) (Unikie AI vision, n.d) 

![unikie](/assets/images/Unikie.png)
##### Unikie AI Vision toimii antureiden ja sovellusten aivoina (Unikie AI vision n.d)
<p>&nbsp;</p> 

Unikien autonomiset ajo- ja ohjausratkaisut mahdollistuvat AI Visionin joustavilla ja monipuolisilla sovellusohjelmointirajapinnoilla. (Automated factory parking, n.d) 

<p>&nbsp;</p> 
### RustDDS

Atostek perustettiin Tampereelle vuonna 1999. Nykyisin sillä on toimisto Tampereen lisäksi myös Espoossa. Yritys on ohjelmistoalan asiantuntija, jolla on kokemusta terveyden ja lääketieteen sovellusten, teollisuuden tuotekehityksen sekä julkisen sektorin IT-konsultoinnista. (Atostek Oy, n.d) (Ohjelmistoalan asiantuntija, n.d) 

Atostek on ollut mukana kehittämässä Roclan automaattitrukkia ”Vihivaunua”. Vihivaunu on osa automaatiojärjestelmää, joka voidaan asentaa varastoihin ja logistiikkakeskuksiin. Järjestelmä suunnittelee trukkien reitit optimoiden ne automaattisesti. Trukkien liikkeitä ja akkujen varausta optimoidaan reaaliaikaisesti, jolloin liikenneruuhkia ei synny ja toimintavarmuus säilytetään. Yritys on myös tehnyt yhteistyötä Kalmar:in kanssa luoden ohjelmistoja ja algoritmeja, joiden avulla konttienkäsittelylaitteet on muutettu roboteiksi, joiden ohjaus tapahtuu sataman toiminnanohjausjärjestelmällä. Järjestelmän avulla ohjelmistot suunnittelevat ja järjestävät konttien siirrot, robottien ajoreitit ja toteuttavat koneiden liikkeet. Konttisataman toimintavarmuus lisääntyi ja sen toiminta on ennakoitavampaa. (Roclan automaattitrukkien ohjausjärjestelmän..., 2019) (Tehokkuutta ja toimintavarmuutta..., n.d) 

ROS 2 ei ole saatavilla puhdasta RustDDS:seä (Rust Data Distribution Service)  joten Atostekilla työstetään RustDDS:sea joka on verkostoitunut (networking?) väliohjelmisto Rust-ohjelmointikielellä toteutettuna (Kuva  ).  

![rust](/assets/images/RustDDS.png)
##### Esimerkki ROS2-liitännästä DDS-moduulia käyttäen (Module rustdds::dds, n.d.)
<p>&nbsp;</p> 

Rust tarjoaa saman suorituskyvyn kuin C++, mutta on huomattavasti vähemmän altis ohjelmointivirheille, mikä tekee siitä ideaalin robotiikan kriittisiin sovelluksiin. RustDDS julkaistaan Apache 2.0-lisenssinä, joka antaa oikeuden käyttää, kopioida, jaella, muokata, myydä, alilisensoida sekä tehdä johdannaisia. Ainoana vaatimuksena on tekijänoikeuksien sisällyttäminen ja muokattujen tiedostojen merkitseminen. RustDDS on saatavilla GitHubista, <https://github.com/jhelovuo/RustDDS> sekä crates.io:sta, <https://crates.io/crates/rustdds> 

![rust](/assets/images/rust_koodi.png)
##### Rustdds :: ros2::RosNode (Struct rustdds::ros2::RosNode, n.d.)
<p>&nbsp;</p> 

Koodi (Kuva ) sisältää tarvittavat lukijat ja kirjoittajat rosout- ja parametritapahtumien aiheisiin sisäisesti luoden ROS2 aiheen ja hoitaa tarvittavat konversiot DDS:sestä ROS2. Atostekilla on omat ROS 2 konsultointipalvelunsa, joihin kuuluvat ohjelmistokehitys, etenemissuunnittelu, käyttöönottoavustus, konseptitodistus sekä demo sovellus. (ROS 2 Consulting, n.d) 
<p>&nbsp;</p> 

### Reaaliaikaisia ohjelmistoratkaisuja autoteollisuudelle

Basemark Oy toimittaa reaaliaikaisia ohjelmistoratkaisuja ja ammattitaitoisia palveluja autoteollisuudelle. Se on yksityinen osakeyhtiö, joka perustettiin vuonna 2015 ja sen päämaja sijaitsee Helsingissä työllistäen yli 50 kansainvälistä ammattilaista. Sillä on kaksi tytäryhtiötä joista toinen, Basemark Inc. on rekisteröity Yhdysvaltojen Delawaressa ja toinen, Basemark GmbH on rekisteröity Saksan Münchenissä. 2019 yhtiö yli kaksinkertaisti liikevaihtonsa ollen yli 8 M€. Yhtiön tuotteita ovat mm. rocksolid, rocksolid compute, BATS sekä GPU- ja web-benchmarkkaus. Yrityksessä käytetään ROS:ia lähinnä protoiluun. (Basemark is a..., n.d.)

Rocksolid on väliohjelmisto grafiikka ja laskentasovellusten kehittämistä varten (Kuva ). Se on optimoitu sulautetuille ja operaatioiden kannalta kriittisille sovelluksille kuten autonominen ohjaus ADAS- (Advanced Driver Assistance Systems) ja HMI-laitteille (Huhan Machine Interface) kuten digitaalisille mittaristoille, Augmented Reality Heads Up Displays (AR HUD), In-Vehicle Infotainment (IVI), digitaaliset peilit sekä takaistuimen viihdejärjestelmät. Rocksolidin ainutlaatuinen patentoitu suunnittelu mahdollistaa grafiikan ja laskutoimitusten samanaikaisuuden johtaen järjestelmätason merkittäviin turvallisuus-, suorituskyky- ja virrankulutushyötyihin. Rocksolid tukee suosituimpia käyttöjärjestelmiä, jolloin se voidaan integroida monenlaisiin RTOS-ympäristöihin. (rocksolid proving graphics..., n.d.) 

![rocksolid](/assets/images/rocksolid.png)
#####  Rocksolidin digitaalisen mittariston referenssi suunnitelma (rocksolid proving graphics..., n.d.)
<p>&nbsp;</p> 

Rocksolid Compute taas tarjoaa kehitteillä olevan C++ laskenta API:n. Lisensoitavaksi on saatavilla jo useita kirjastoja ja toteutuksia. Se on laitteistoagnostinen API, joka mahdollistaa korkeamman tuottavuuden ja helpommin uusin ympäristöihin siirrettävän koodin. Ajatuksena on piilottaa takaosat (vai back-end) kehittäjiltä, jolloin he voivat keskittyä vain algoritmien kehittämiseen. (Rocksolid compute, n.d.) 

![rocksolid](/assets/images/bats.png)
##### Todellisia työmääriä (BATS the essential..., n.d.) 
<p>&nbsp;</p> 

BATS on ammattimainen autojen SoC-suorituskyvyn (System on Chip) arviointityökalu. Sen avulla voidaan nopeasti konfiguroida ja suorittaa monimutkaisia testausskenaarioita kohdejärjestelmissä ja analysoida niiden tuloksia. Se on suunniteltu tarjoamaan objektiivista tietoa ja mahdollistamaan erilaisten järjestelmäpiirien ammattimainen analysointi. BATS sisältää todellisia työmääriä konenäölle, mittaristoille sekä IVI-laitteille (Kuva ). Realististen järjestelmäarviointien suorittamiseksi testit voidaan suorittaa rinnakkain. (BATS the essential..., n.d.)

Basemark suorittaa laajasti laitteiden, alustojen sekä ohjelmistojen suorituskykytestausta. Tässä käytetään Rocksolid Engineä ja tulokset julkaistaan heidän omalla vertailualustallaan. GPUScore on kehitteillä oleva aivan uudenlainen erittäin realistinen suorituskykytestaus. Basemark GPU on arviointityökalu, jolla arvioidaan ja verrataan grafiikan suorituskykyä mobiili- ja pöytäkonealustoilla. Basemark Web 3.0 taas on kattava verkkoselaimen suorituskykytestaus, jonka avulla testataan matkapuhelimen tai pöytäkoneen kykyä käyttää verkkopohjaisia sovelluksia. (Benchmarks & tests, n.d.) 


<p>&nbsp;</p>  
# Alan tutkimus ja kehitys

Kiinnostus ROS-robottiekosysteemiin on suurta ympäri maailman. ROS:n käytössä vain mielikuvitus vaikuttaa olevan rajana. Erilaisia tutkimus- ja kehitysmahdollisuuksia on jo melkein joka lähtöön.   

<p>&nbsp;</p> 
## ROS health

Ikääntyvä väestö luo terveydenhuollolle haasteita, sillä työvoima vähenee ja kustannukset kasvavat. Vanhustenhoidon automatisoinnin ja tuen markkinat voivat kasvaa suuriksi sillä haasteita on mm. potilaiden kävelyttämisessä, kuulemisessa ja hoidossa, aina osastolla ja kotona tapahtuvaan valvontaan. Robotiikan avulla työntekijät voivat lisätä kliinisen työn määrää ja vähentää aikaa, joka kuluu toimitettaessa tavaroita potilaille. (Meertens, 2019) 

Useiden eri toimijoiden robottilaivueet ovat iso haaste. Eri toimijoiden laitteet toimivat samoissa tiloissa, esim. aterioiden- ja tavaroiden jakelurobottien on kuljettava samoihin tiloihin ja jokaisella toimittajalla on oma liikenne-editori. Editorissa sairaalan on ilmoitettava missä robotit voivat liikkua ja missä ovat esim. hissit ja automaattiset ovet. Saman toimijan laitteet osaavat jo toimia sulavasti keskenään, mutta usean eri toimijan laitteet eivät kommunikoi keskenään aiheuttaen robottiruuhkia hissiauloissa ja oviaukoissa. Mikäli kaluston hallintarajapinta voi asettaa reittejä robottien reittipisteisiin, voidaan tilannetta parantaa. Monilla robotin toimittajilla ei kuitenkaan ole olemassa olevaa kaluston hallintaa, ja ne tukevat vain yksinkertaisia käskyjä kuten päälle/pois toiminto. Open Robotics työskentelee FreeFleet nimisen yhdistetyn integraatiojärjestelmän parissa. Käyttäjä voi lähettää robotin määränpäähän ja älykäs kalustosovitin keskustelee myyjäkohtaisen kalustonjohtajan kanssa. (Meertens, 2019) 

Voidaan säästää jopa vuosia aikaa, yhdistämällä laivueiden käyttöönottoja ja luomalla paketteja, joita voidaan käyttää uudelleen alustojen välillä. Open Robotics-säätiö kehittää ROS health-alustaa, jonka on tarkoitus tarjota turvallisia viestejä olemassa olevien sovellusten välillä. Siinä on komentorivikäyttöliittymä, käyttöliittymäpaketteja, kyky käsitellä liikennettä ja useiden sovellusten jaettava reitin suunnittelu. Paketin nimi on System of Systems Syntehesiser (SOSS) ja sen hyötyjä ovat kaluston yhteensopivuus, optimointi sekä skaalautuvuus. (Meertens, 2019) 

ROS health sisältää kahdenlaisia käyttöliittymiä. Suoratoisto käyttöliittymä näyttää monien eri robottilaivueiden robottien sijainnin käyttäen Websocket-verkkotekniikkaa, joka mahdollistaa kaksisuuntaisen yhteyden selain- ja palvelinohjelmistojen välille TCP-yhteydellä. Mobiililaitteiden käyttöliittymällä hoitajat saavat potilaita koskevat hoitotiedot nopeasti ja voivat antaa roboteille erilaisia komentoja. HL7-protokollaa (Health Level Seven) käyttävät useimmat sairaalasovellukset ja Open Robotics loi kerroksen, joka muuntaa protokollan viestit ROS-viesteiksi, jolloin ROS 2 voi muodostaa yhteyden olemassa oleviin sairaalasovelluksiin DDS-protokollan avulla. (Meertens, 2019) 

<p>&nbsp;</p> 
## Mikrokirurginen robotin tutkimusalusta

The Hamlyn Centre for Robotics Surgery, Imperial College Lontoossa on yksi kuudesta Institute of Global Health Innovation’s (IGHI) tutkimuskeskuksista, jotka tukevat terveydenhuollon innovaatioiden tunnistamista, kehittämistä ja levittämistä. (About us, 2020) Nykyisin saatavilla olevat mikrokirurgisten taitojen kehittämistä ja nopeuttamista tukevat robottiavusteiset mikrokirurgian (RAMS, Robot-Assisted Micro-Surgery) koulutusalustat on pääsääntöisesti suunniteltu makromittakaavassa minimalistisen invasiiviseen leikkaukseen. Siksi Hamlyn Centre on nähnyt tarpeelliseksi kehittää oma mikrokirurgisen robotin tutkimusalusta. He kehittävät mikrokirurgista robotin tutkimusalustaa (MRRP, Microsurgical Robot Research Platform) joka sisältää orjarobotin, jossa on kaksikätinen manipulaattori, kaksi pääkontrolleria sekä näköjärjestelmä (Kuva  ). Se tukee joustavasti monia mikrokirurgisia työkaluja. Ohjelmiston arkkitehtuuri pohjautuu ROS:iin, jota voidaan laajentaa. Eri rajapintoja tutkimalla päädyttiin valitsemaan isäntä-orja-kartoitusstrategia. (Zhang, et al., 2019)  

![Kirurgirobo](assets/images/Kirurgirobot.png)
##### Orjarobotin CAD malli MRRP:lle (Zhang & al., 2019)
<p>&nbsp;</p> 

Orjarobotin kinemaattinen ohjaus perustuu SmarPod API:iin (Application Programming Interface) (Kuva   ). Modulaarista ohjausjärjestelmää käytetään ohjaamaan orjarobottimanipulaattorien pietsomoottoreita samalla kun alemman tason muodostavat kaksi harjatonta DC moottorinohjainta käytetään ohjaamaan moottoroituja mikroatuloita. Suuntauksen ohjaamiseksi ohjausjärjestelmällä voi olla 1 kHz näytteenottotaajuus. 

![Ohjelmistoarkkitehtuuri](/assets/images/Ohjelmistoarkkitehtuuri.png)
##### Ohjelmistoarkkitehtuuri MRRP:lle (Zhang & al., 2019)
<p>&nbsp;</p> 

Järjestelmässä käytetään ROS väliohjelmistoa MRRP yhteyden luomiseksi. He kehittivät ROS-to-SmarPod API-sillan komponenteilla, jotka julkaisevat robotin tilat ROS-sanomina. Reaaliaikainen kinemaattinen ja visuaalinen data voidaan tilata ROS-viesteinä korkeatasoisen apuprosessin saamiseksi. Päämanipulaattorin ohjauskomennot, joita järjestelmä tuottaa ihmisten tai älykkään järjestelmän välityksellä voidaan julkaista ROS topiceina jotta MRRP- robotin päätelaite saadaan asetettua haluttuun asentoon karteesisessa tilassa. Kädessä pidettävällä isäntäohjaimella operatiiviset käskyt generoidaan OpenCV:hen perustuvalla liikkeenseuranta moduulilla. Laskenta ja käsittely on toteutettavissa Python, C++ ja C-ohjelmointikielillä. Käyttöliittymien kehittäminen mahdollistuu QT-pohjaisella GUI:lla. (Zhang, et al., 2019) 

<p>&nbsp;</p>  
## Kappaleen piirteiden havaitseminen

Saksassa sijaitseva Soutwest Research Institute:n (SwRI) ROS Industrial-tiimi kehittää 3D-tunnistinjärjestelmiin hybridia lähestymistapaa, jossa kehittyneet 2D-tunnistimet integroidaan ROS 3D-tunnistuslinjalle kappaleen piirteiden havaitsemiseksi ja jotta tunnistin voidaan päivittää joustavasti ilman muutoksia muuhun järjestelmään. Teollisissa sovelluksissa on usein 3D-havaintodataa 3D-syvyyskameroista, jotka tuottavat myös 2D-video suoratoistoa. ROS-työkaluilla tuota 2D-video suoratoistoa voidaan käyttää haluttujen kappaleiden havaitsemisemiseksi ja projisoida ne takaisin 3D-dataan. Semanttisesti merkityn 3D-verkon aikaansaamiseksi tunnistetut piirteet voidaan yhdistää skannauksen aikana. Verkon päälle voidaan generoida työstöratoja, jotka saadaan havaituista kappaleista. Lähestymistavan arvioimiseksi kehitettiin esimerkki hitsausmenetelmä, jossa jokainen osa oli sarja kiinnehitsattuja alumiinilevyjä, mutta joiden tarkkaa kokoa tai sijaintia ei tiedetty. (Powelson, 2020) (Kuva  ) 

![Hitsauskoe](/assets/images/Hitsauskoe.png)
##### Kokeellinen hitsausmenetelmä (SwRI, 2020)
<p>&nbsp;</p> 

Järjestelmä etenee käyttäen ROS-työkaluja. Aluksi kameraohjain toimittaa värillisen pistepilven TSDF-solmulle (Truncated Signed Distance Field), joka rekonstruoi ympäristön geometrian. Samalla pistepilviä huomioiva solmu erottelee pikseliin kohdistetun 2D-kuvan pistepilvestä ja lähettää sen ROS-palvelun kautta satunnaisille 2D-tunnistimille, joka palauttaa naamion, jossa on leima jokaiselle kuvapikselille. Näitä leimoja uudelleen värjätään pistepilven merkitsemiseksi. Tulokset voidaan yhdistää avoimen lähdekoodin octomap_serveriä käyttämällä. Skannauksen lopussa YAK-kirjasto toimittaa 3D-verkon ympäristöstä ja octomap antaa octomapin, joka on väritetty semanttisilla leimoilla. Tesseract-törmäyksen tarkistusrajapintoja voidaan käyttää havainnoimaan kolmioverkkoon liittyvät vokselit, jolloin geometrinen verkko lisätään semanttiseen dataan. (Powelson, 2020) 

![Hitsikuvat](/assets/images/Hitsikuvat.png)
##### Vasemmalla näkyy 2D kuva ja havaittu sauma. Oikealla näkyy 3D-verkko ja yhdistetty 3D havaittu hitsaussauma (SwRI, 2020)
<p>&nbsp;</p> 

<p>&nbsp;</p>  
## Ascento: kaksipyöräinen hyppäävä robotti

Sveitsissä joukko insinööriopiskelijoita ETH (Eidgenössische Technische Hochschule Zürich) Zürichin tutkimus instituutista on kehittänyt tasapainottelevan kaksipyöräisen robotin. Ascenton (Kuva  ) rakennekomponentit luotiin topologisella optimoinnilla (Kuva   ) ja ne on kokonaan 3D-tulostettu polyamidi 12, käyttäen selektiivistä lasersintraus tekniikkaa. (Coxworth, 2020) 

![Ascento](/assets/images/Ascento.png)
##### Ascento (Ascento Indoor Mobility..., 2020) 

![Topologia](/assets/images/Topologiset.png)
##### Topologialla optimoitu osa (Ascento Indoor Mobility..., 2020) 
<p>&nbsp;</p> 

Jalkojen optimoitu geometria erottaa ajo- ja hyppyliikkeet antaen näin robotin taipua erilaisissa tippumisskenaarioissa. LQR (Linear Quadratic Regulator) kontrollerilla saavutetaan vakaa ajo. Palautuakseen erilaisista hyppy- tai tippumisliikkeistä robotti käyttää peräkkäismyötäkytkentäistä säätökontrolleria, jossa on takaisinkytkennän seuranta. Ascentossa on keskusyksikkönä Intel NUC i7, IMU (Inertial Measurement Unit) sekä mikrokontrolleri mahdollistamaan yhteydenpito tietokoneen ja IMU:n välillä. Moottorien virrankulutukseen on akku, joka koostuu neljästä sarjaan kytketystä kolmekennoisesta litiuminonipolymeeriakusta (LiPO). Tietokone ja muut elektroniset laitteet saavat virtansa neljäkennoisesta LiPO akusta. Ohjelmiston on oltava laskennallisesti tehokas, jotta suuren kaistanleveyden ohjaimet mahdollistuvat. Kaikki ohjelmistot on kirjoitettu C++:lla. ROS:sia käytetään korkean tason viestintään. Kalman suodatin toimii IMU:n ja moottorin kooderi mittauksista saaduilla anturitiedoilla. Ascentoa voidaan kauko-ohjata, mutta se voi myös operoida täysin autonomisesti käyttäen kameroita ja antureita. Se painaa 10.4 kg ja sen huippunopeus on 8 km/h. Suurin mahdollinen hyppykorkeus on 0.4 m ja operointiaika on n. 1,5 h. (Coxworth, 2020) (Klemm, ym., 2019) 

<p>&nbsp;</p> 
## Hedelmäpuiden leikkausrobotti

Saksassa sijaitseva Hohenheimin yliopisto kehittää autonomista hedelmäpuiden leikkausrobottia (Kuva  ). Keski-Euroopassa on paljon hedelmätarhoja, joiden viljely ei ole taloudellisesti kannattavaa ja valtaosa on huonosti hoidettu tai niitä ei ole hoidettu lainkaan. Pelkästään Saksassa omenatarhat tuottavat 500 000–1 000 000 tonnia omenoita satovuodesta riippuen. Säännöllisellä ja ammattimaisella leikkauksella puiden terveyttä ja pitkää ikää voidaan kuitenkin edesauttaa. Vaikka erilaiset maatalouskoneet kuten mm. puiden ravistelijat ja korjuukoneet ovat suurena apuna sadon korjuussa on puiden karsinta kuitenkin vielä suoritettava käsin. Maataloustekniikan instituutissa työskentelevä tohtori David Reiser työskentelee yhdessä tohtoriksi opiskelevan tutkimusavustaja, Jonas Boysenin kanssa tekoälyprojektissa, jossa robottia kehitetään niin, että se voi suorittaa puunleikkauksen suurelta osin itsenäisesti. (Scott, 2021) (Stuhlemmer, 2021)​ 

![hedelma_robo](/assets/images/hedelma_robo.png)
###### Hedelmäpuun leikkausrobotti (Schmid, 2021) 
<p>&nbsp;</p> 

Kolme tutkijaa asensi jo olemassa olevaan mobiiliprototyyppiin teollisissa tuotantolinjoissa käytetyn robottikäsivarren, jolla on monta vapausastetta. Robottikäsivarteen on asennettu kamera ja erityisiä antureita, jotka auttavat navigoimaan ja tunnistamaan puita ja niiden muotoja. LiDAR:lla skannataan ympäristöä ja mitataan etäisyyttä esineisiin. (Scott, 2021) (Stuhlemmer, 2021) 

![hedelma_robo](/assets/images/3D-malli.png)
##### Robotin ottama 3D-malli (Schmid, 2021) )
<p>&nbsp;</p> 

Monista yksittäisistä etäisyysmittauksista luodaan pistepilvi, joka kuvaa puun kolmiulotteista rakennetta. Saatu kuva tallennetaan analysointia varten (Kuva ). 

![hedelma_robo](/assets/images/erikoisaisa.png)
##### Erikoisvalmisteinen aisa (Schmid, 2021) 
<p>&nbsp;</p> 

Erikoisvalmisteisen aisan (Kuva  ) avulla teleskooppivarteen kiinnitetyn moottorisahan asentoa voidaan siirtää oikeaan leikkausasentoon. Tutkijat opettavat parhaillaan tietokonetta sijoittamaan saha oikeaan paikkaan. Puulajista ja määräpaikasta riippuen on olemassa erilaisia leikkaustapoja. Käyttäjän pitäisi myöhemmin kyetä valitsemaan karsitaanko vain oksia vai lyhennetäänkö runkoa, jolloin saadaan puu haarautumaan enemmän. Robottia on edelleen ohjattava manuaalisesti, mutta pitkän aikavälin tavoite on, että se toimisi itsenäisesti ja kykenisi leikkaamaan oksia jopa 7 m korkeudesta. (Scott, 2021)  (Stuhlemmer, 2021) 

<p>&nbsp;</p> 
## Forschungszentrum Informatik (FZI) 

Saksan Karlsruhessa sijaitsee voittoa tavoittelematon tietotekniikan tutkimuskeskus, joka on perustettu vuonna 1985 ja joka tekee läheistä yhteistyötä paikallisen yliopiston KIT:n (Karlsruhe Institute of Technology) kanssa. ROS-Industrialin jäsenenä he kehittävät ja integroivat uusimpia ratkaisuja reaalimaailman sovelluksiin. (FZIChannel, 2021) (FZI, n.d.)​ 

### HORSE - Collaborative Screw Assembly 

HORSE on älykäs integroitu robotiikkajärjestelmä pk-yrityksille, joiden valmistusprosesseja ohjataan IoT:n avulla.  Sen tarkoituksena on edesauttaa yrityksiä tekemään tuotantolinjoistaan joustavia ja monipuolisia. Älykkäässä tehtaassa ihmisten, robottien, AGV:ien (Autonomous Guided Vehicles) sekä koneiston tehtävien tehokasta toteuttamista kehitetään ja validoidaan. Valmistava teollisuus ja erityisesti pk-yritykset kokevat suurta painetta lisätä tuotantoa ja tehokkuutta. Nämä ovat suoraan kytköksissä tehtaan joustavuuteen. Industry 4.0 kehitykseen kuuluvat mm. edistynyt robotiikka, IoT:in kyberfyysiset järjestelmät. Tästä huolimatta tehtaiden joustavuus ei ole lisääntynyt. Robottien käyttö ei ole riittävän joustavaa ja tehokasta. Turvallisuusmääräykset pitävät robotit ja ihmiset edelleen erillisissä tiloissa, eikä yhteistyörobottien ilmaantuminen ole ratkaissut turvallisuuskysymyksiä, ellei niitä tueta oikeanlaisella teknisellä ympäristöllä. Työnjakoerittely ihmisen ja robotin välillä lisää joustamattomuutta, sillä kummallakin on omat tehtävänsä eikä niitä ole helppoa vaihtaa dynaamisesti. Tämä johtaa resurssien epäoptimointiin. Lisäksi robottien ohjausprosessit ovat usein huonosti kokonaisuuteen integroituja. HORSE-projekti tarjoaa joukkoa ratkaisuja edellä mainittuihin ongelmiin. Tutkimus on saanut rahoitusta Euroopan Unionin Horizon 2020 ohjelmasta. (About HORSE, 2017)

Jotta Euroopan teollisuus pysyy kilpailukykyisenä maailmanlaajuisesti, on sen omaksuttava Industry 4.0 ja sen mukanaan tuomat tekniikat kuten yhteistyörobotit, AGV:t, AR-tuki sekä älylaitteet. Suuryrityksille tämä on hyvinkin suoraviivaista mutta pk-yrityksillä saattaa olla prosessissa moniakin eri vaikeuksia, joita ovat mm. asiantuntemuksen kuten korkeasti koulutetun työvoiman ja resurssien puute sekä haluttomuus muutoksiin sillä digitalisoinnin edut eivät ole aina niin selkeästi nähtävillä prosessin sisältäessä paljon muutakin kuin vain teollisen robotin ostamisen ja käyttöönoton. HORSE-kehys on projektin aikana otettu käyttöön 10 eri tuotantolaitoksessa eri puolilla Eurooppaa (Kuva  ). (HORSE Framework, 2017)  

![horse](/assets/images/horse.png)
##### Tuotantolaitokset ympäri Eurooppaa (HORSE Framework, 2017)
<p>&nbsp;</p> 

HORSE-kehys perustuu RAMI-arkkitehtuurimäärityksiin (Reference Architectual Model Industrie) ja on yhteensopiva IoT:in arkkitehtuurin ja sen konseptien kanssa. Se tarjoaa viitearkkitehtuurista suunnitelmaa kyberfyysisen järjestelmän sekä teknologisen asemoinnin yhdistämiseen. Hybridituotanto integroi ihmisen ja robotin toimijat saumattomasti pystysuuntaisiin tuotantosoluihin kytkettynä vaakasuoraan alusta loppuun tuotantoprosessiin. (HORSE Framework, 2017)

Kolme pilottitehdasta on ollut mukana projektin alusta saakka. He ovat esittäneet tarvittavia vaatimuksia ja he ovat auttaneet HORSE-kehyksen suunnittelussa. Siten on määritelty innovatiivisia ja haastavia tapauksia, jotka kuvaavat tehtaiden todellisia ongelmia. Ensimmäisessä vaiheessa mukana oli pilottitehtaita Puolasta, Espanjasta sekä Hollannista. Tässä tutustumme vain edellä mainittuihin pilotointeihin. (Pilots, 2017) 

Toisessa vaiheessa, projektin ollessa puolivälissä mukaan on otettu 7 muuta pk-yritystä. RTO (Recovery Time Objective) tai integraattorit ovat tukeneet tehtaita, jotta voitaisiin demonstroida kuinka HORSE-kehyksen hyväksymisellä ja uusien komponenttien käyttöönotolla voidaan lisätä tehtaiden joustavuutta, puuttua nykyisiin ongelmiin sekä edistää digitalisoitumista tuotannon muissakin vaiheissa.(HORSE Factories, 2017)   

#### Robotic based quality (visual) inspection and human-robot co-manipulation (BOSCH) 

Robert Bosch España, Fábrica de Castellet valmistaa lasinpyyhkijöiden kokoonpanoja (Kuva   ) ja pilotti on omistettu autoteollisuudelle. Tuulilasinpyyhkijöitä on oltava monia erilaisia ja -kokoisia riippuen auton mallista. Yksi tuotantolinja koostuu useista eri työasemista, joista noin 7 on täysin automatisoitua, yksi on puoliautomaattinen ja lopussa on 5 manuaalista työasemaa. Linjasto työskentelee jaksoissa, jotta eri komponentit saadaan koottua. Pilotissa keskitytään tuotantolinjan viimeiseen työasemaan, joka on yksi pullonkauloista. (Robotic based quality..., 2017) 

![horse](/assets/images/lasinpyyhkija.png)
##### Lasinpyyhkijöiden kokoonpano sekä toimituslaatikko (HORSE, n.d.)
<p>&nbsp;</p> 

Jokainen tuote on visuaalisesti tarkistettava ja asetettava toimituslaatikkoon (Kuva  ). Prosessi on pysynyt manuaalisena (Kuva  ) työntekijöiden joustavuuden ja sopeutuvuuden vuoksi. Työ aiheuttaa terveysvaaroja ja -ongelmia, jotka vahingoittavat selkää, ranteita sekä vahingoittaa käsivarsia ja sormia. (Robotic based quality..., 2017) 

![horse](/assets/images/tyoasema.png)
##### Manuaalinen työasema (Robotic based quality..., 2017) 
<p>&nbsp;</p> 

Boschin, KUKA:n, TUE:n (Eindhoven University of Technology), TUM:in (Technical University of Munich) ja TNO:n (the Netherlands Organisation for applied scientific research) asiantuntijat ovat suunnitelleet HORSE-projektiin robottijärjestelmän, jossa ei ole aitoja. Se noutaa tuotteen, tarkistaa laadun ja sijoittaa oikealla tavalla toimituslaatikkoon. Ihmisten ja robottien välistä yhteistyötä ohjataan ja valvotaan valmistusprojektin hallintajärjestelmällä. Järjestelmän avulla varmistetaan oikea toimintajakso. Turvallisuutta on lisätty FZI:n solunvalvontajärjestelmällä. ((Robotic based quality..., 2017)

Projektin haasteita olivat mm. käyttäjän turvallisuus ja tuotteiden laatu vaaditulla jaksolla, monet eri tuotemitat ja painot sekä asiakkaiden pakkausten monimuotoisuus, yhteensopivuus järjestelmien ja vakiovarusteiden välillä sekä ratkaisun kestävyys. Haasteisiin kehitettyjä ratkaisuja ovat pyyhkimien automaattisesti tapahtuva laadunvalvonta sekä pakkaaminen, AR:n käyttäminen apuna hylkyyn menneiden osien tarkistamiseen sekä robottien ja ihmisten tehtävien organisointi ja seuranta, johon kuuluvat matkapuhelin viestit (Kuva  ). (Robotic based quality..., 2017)

![horse](/assets/images/linjasto.png)
##### HORSE ratkaisu linjaston pullonkaulaan (Robotic based quality..., 2017)
<p>&nbsp;</p> 

Ratkaisusta saatuja hyötyjä ovat: pienentyneet stressikuormat käyttäjille, parantuneet työolot, fyysisten vammojen riskien minimointi sekä parantunut joustavuus. HORSE kykenee järjestämään tuotantolinjat nopeasti uudelleen ja vaihtamaan osien kokoonpanon ja niihin liittyvien tuotantotyökalujen sijainnin. Tuotannon seisauksien kesto uudelleenkonfigurointia varten lyhenee. Lisäksi projektin hyötyjä voidaan potentiaalisesti kopioida BOSCH:in tehtailla ympäri maailman. (Robotic based quality..., 2017)
<p>&nbsp;</p> 

#### Robot-human hybrid position/force control co-working applications (Odlewnie Polskie SA) 

Odlewnie Polskie tuottaa vuosittain n. 16 tuhatta tonnia valurautavaluja, joiden paino vaihtelee 2 kilosta 100 kiloon. Heillä on n. 990 erityyppistä valua eri kokoonpanoihin ja käyttötarkoituksiin. Suurin osa tuotannosta on koneellistettu ja automatisoitu. Tehtaan suurin ongelma on työntekijöiden työolojen parantaminen. Viimeistelytoimenpiteet kuten purseenpoisto, puhtaaksileikkaus sekä valuerotus suoritetaan pääsääntöisesti manuaalisesti (Kuva  ) ja tämä aiheuttaa vakavia ongelmia työolojen, tuki- ja liikuntaelinsairauksien, pölyn, melun ja onnettomuuksien vuoksi. Koko valuprosessissa viimeistely aiheuttaa suuria kustannuksia. (Robot-human hybrid position/force..., 2017)

![horse](/assets/images/valun_viimeistely.png)
##### Valun viimeistelyä manuaalisesti. (Robot-human hybrid position/force..., 2017)
<p>&nbsp;</p> 

HORSE-sovelluksen yhtenä haasteena oli automatisoida toiminta ja tehdä prosessista nopeampi, tehokkaampi ja parantaa työtekijöiden oloja. Toinen haaste oli saada automaatio kattamaan tuo yli 900 tuotteen valikoima. Sovelluksen avulla halutaan myös lisätä joustavuutta, konfiguroitavuutta sekä yleistä turvallisuutta. Keskittymällä suoraan tuotanto-organisaation rajapintaan OSGI:n (Open Service Gateway Initiative) ja ROS:n kautta ihmisten ja robottien yhteistyötä pyritään organisoimaan, jotta kriittisimpiä vaiheita voidaan suorittaa turvallisemmin. (Robot-human hybrid position/force..., 2017) 

Projektin haasteita olivat valuraudan leikkausprosessin automatisointi laadun ja joustavuuden parantamiseksi, demonstroimalla tapahtuvan oppimisen omaksunta, jotta uudelleen ohjelmoitua rataa voidaan käyttää eri tuotteille, viallisten osien määrän vähentäminen, työolojen parantaminen sekä loukkaantumisriskien pienentäminen. Ongelmiin saatuja ratkaisuja ovat mm. uusien valukappaleiden esittely opettamalla, automaattinen metallivalujen leikkaus, työtekijöiden turvallisuuden ja mukavuuden varmistus sekä joustava tuotanto, joka mahdollistaa suuren määrän erilaisia valuja (Kuva  ). (Robot-human hybrid position/force..., 2017)

![horse](/assets/images/autosiistiminen.png)
##### Metallivalujen automatisoitu siistiminen (Robot-human hybrid position/force..., 2017)
<p>&nbsp;</p> 

Ratkaisun tuomia hyötyjä ovat olleet vähentynyt työntekijöiden tarve, parantunut kappaleiden laatu ja lyhentynyt tuotantoaika, työolojen merkittävä parantuminen sekä korkean teknologian mukanaan tuoma parempi asema valimomarkkinoilla. (Robot-human hybrid position/force..., 2017)  

#### Flexible assembly with mobile robot (Thomas Regout International, TRI) 

Thomas Regout International BV on hollantilainen räätälöityjen teleskooppikiskojen (Kuva  ) valmistukseen erikoistunut yritys. Muotoilu, rei’itys sekä kokoonpano on puoliautomaattista. Pienien tuotantoerien vuoksi työntekijöiden on vaihdettava koneita ja työkaluja eri tuotteiden välillä. Tämä taas puolestaan vie aikaa ja aiheuttaa virheiden tekemisen riskin. Lisäksi heidän on ratkaistava ongelmat hyvin lyhyessä ajassa ja annettava tuotteesta ja prosessin suunnittelusta palautetta insinööreille ja johdolle. Tämä vaatii joustavaa automaatiota ja tuotannon kokonaishallintaa.  (Flexible assembly with..., 2017) 

![horse](/assets/images/teleskooppikisko.png)
##### Teleskooppikisko (Flexible assembly with..., 2017) 
<p>&nbsp;</p> 

Kiskojen profiilit on valmistettu teräskeloista ja korroosion estämiseksi ne pintakäsitellään. Käsittelyä varten kiskot on kerrostettava yksi kerrallaan. Kiskot asetellaan räkkiin manuaalisesti koska niiden mitat ovat hyvin erilaisia (Kuva  ).  (Flexible assembly with..., 2017)  
 
![horse](/assets/images/pintakasittely.png)
##### Kiskojen asettelu pintakäsittelyä varten. (Flexible assembly with..., 2017) 
<p>&nbsp;</p> 

Työvoiman tarve on suuri ja työllä on suuri fyysinen vaikutus sen tekijöihin. HORSE-kehys ja robottisovellus toimivat samalla alueella ihmisten kanssa keräten profiileja räkkiin. Yhteistyökumppaneina toimineiden TNO:n ja TRI:n asiantuntijat ovat suunnitelleet ratkaisussa käytetyn KUKA:n robottikäsivarren. Valmistusprosessimalli on suunniteltu seuraamaan tuotantoa ja jakamaan tehtävät vuorotellen työntekijälle ja robotille. Tuotantosolua valvotaan antureilla, jotka varoittavat työntekijää ja turvallisuusinsinööriä, mikäli jokin riski havaitaan. (Flexible assembly with..., 2017)  

Projektin haasteita olivat mm. miten tuetaan TRI:n yritysstrategiaa kasvattamalla joustavuutta ja vähentämällä tuotantokustannuksia, työntekijäportaan visuaalinen hallinta, mikäli MES (Manufacturing Execution System) ei riitä, Pick & Place yksikön korvaaminen aidattomalla älyrobotilla, raskaan työn kuormituksen vähentäminen korvaamalla ihmiset robotilla sekä miten vähentää työkalujen valmistelun vaatimaa kokemusta AR:n avulla. Ongelmiin kehitettiin ratkaisuja kuten eri osien automatisoitu koukkuihin ripustus samanaikaisesti ihmisen kanssa, AR-tuki tuotantotyökalujen kokoamiseen ilman kokemusta, seuranta, organisointi sekä suunnittelutuki joustavan ja tehokkaan tuotannon mahdollistamiseksi. Tapauskohtaisia hyötyjä ovat olleet lyhentyneet vaihdot ja vaihtoon kuluva kokonaisaika, tehostunut tuotannon hallinta sekä ihmisten vähentynyt työmäärä. Kokonaisuudessaan projekti on tuonut säästöjä kehitysvaiheeseen, vähentänyt kehityshankkeiden taloudellista riskiä ja luonut pääsyn korkean teknologian tietoon. (Flexible assembly with..., 2017)  
<p>&nbsp;</p> 

### Sim2Log VR Mixed Reality Logistic Automation 

Kasvaneen verkkokaupan myötä logistiikkateollisuus kasvaa dynaamisesti. Siksi niiden on alettava yhä enenevässä määrin automatisoimaan toimintaansa. Yksi keskeisimpiä ratkaisuja ongelmaan on työntekijöiden mahdollisuus suunnitella, ohjelmoida ja validoida robottisovelluksia nopeasti. Osittain Saksan BMBF:n (Bundesministerium für Bildung und Forschung) rahoittama Sim2Log-projekti on yhdessä TruPhysics CmbH:n kanssa tehty tutkimus, jossa kehitetään menetelmiä, joilla virtuaalirobottien suunnittelua, ohjelmointia, testausta sekä sovittamista käyttöalueeseen helpotetaan. Työntekijöiden olisi kyettävä toteuttamaan monimutkaisia automaatioratkaisuja valmiiden logistiikkamoduulien sekä VR- (Virtual Reality) ja AR-simulaatioympäristöjen avulla. (Sim2Log VR, n.d.)

![sim2log](/assets/images/VR_AR.png)
##### Ohjelmointi VR / AR-simulointiympäristössä. (Sim2Log VR, n.d.)
<p>&nbsp;</p> 

Intuitiivisten ohjelmointikonseptien ja innovatiivisten syötemetodien, kuten TruGlove-ohjelmointikäsineen avulla robotit voidaan ohjelmoida ilman paljoakaan ennakko-osaamista. VR-simulaatiossa sovelluksia voidaan ensin suunnitella ja samalla arvioida niiden toteutettavuus (Kuva  ). Ajoitusta säätämällä voidaan määrittää jaksonaika ja siten simuloida kokonaisia prosesseja. Näin kehitetty ratkaisu voidaan siirtää suoraan todelliseen robottiin ja myöhemmin mukauttaa intuitiivisesti AR:n avulla. VR:ssä määriteltyjen liikeratojen toteutus oikeassa robotissa tehdään käyttämällä FZI Motion Pipelinea, ROS-ohjelmistoa, joka on kehitetty helpommaksi ja joustavammaksi roboteille, joissa on ROS-rajapinta. FZI Motion Pipeline tarjoaa käyttäjälle graafisen käyttöliittymän, jossa käytettävissä olevat liikeradat on lueteltu käyttöliittymään ja käyttäjä voi käyttää yksinkertaisia painikkeita liikeratojen lataamiseen, suorittamiseen ja muokkaamiseen. Mikäli liikeradan pistettä on muutettava voi käyttäjä syöttää halutun paikkatiedon tai käyttää robotin pendanttia asettamaan muutettu arvo ja tallentamaan se. Korkean tason määrittelyä varten on integroitu avoimen lähdekoodin käyttäytymismoottori FlexBE joka on myös toteutettu ROS:lla. FlexBE:ssä on graafinen käyttöliittymä, jonka avulla käyttäjän on helppo määrittää robotin työkulku yhdistämällä rakennuspalikat ilman ohjelmointia. Määrityksen tulosta voidaan käyttää oikealla robotilla. (Sim2Log VR, n.d.) 

![sim2log](/assets/images/sim2log_tiedonsiirto.png)
##### Järjestelmän ohjelmistoarkkitehtuuri ja komponenttien välinen tiedonsiirto. (Bolano, & al., 2020)
<p>&nbsp;</p> 

AR-sovellus on pääosin toteutettu Unityssä ja robottikomponenttien ohjauksessa on käytetty ROS:ia. Näiden kahden välinen viestintä on toteutettu käyttäen avoimen lähdekoodin ROS-ohjelmistokirjastoa. Kokonaisarkkitehtuuri näkyy kuvassa ____. Järjestelmässä on mahdollista myös simuloida vain kuljetinhihnalla liikkuvia osia, jolloin todellinen robotti reagoi sovelluksen käyttöliittymässä asetettujen muutosten mukaisesti. Mahdollisuus sisällyttää virtuaalirobotteja simulaatioon antaa käyttäjän arvioida lisävarusteiden tarvetta arvioimalla paras sijainti saavutettavuuden ja hyvien tulosten perusteella. (Bolano, et al., 2020) 

![sim2log](/assets/images/semi_virt.png)
##### Sim2Log VR: Uusien robottisovellusten semi-virtuaalinen suunnittelu ja validointi. (Bolano, et al., 2020)
<p>&nbsp;</p> 

Järjestelmä on otettu käyttöön kokoonpanossa, jossa oli kuljetushihna sekä 6-DOF-käsivarsirobotti 2-sormitarttujalla (Kuva  ). Kiinteästi sijoitetusta kamerasta saatiin reaaliaikaista kuvaa halutusta kohdasta. Kokonaisuuden eteen asetettiin kosketusnäyttö, jotta käyttäjälle kyettiin visualisoimaan lisätty tapahtumapaikka yhdessä GUI:in kanssa. Näin saatiin linjan parametrejä helposti muutettua ja simuloitu robotti lisättyä asetuksiin. Jokaisesta muutoksesta laskettiin ja visualisoitiin tuloksena olevan linjan suorituskyky. Järjestelmää voitaisiin parantaa lisäämällä joustavuutta virtuaalikohteiden määrittelyyn sekä laajentamalla simulaatiossa käytettävää laitteistokirjastoa. AR-kuulokkeiden käyttö voisi tehdä virtuaalikoneiden esityksestä tehokkaamman ilman, että näyttöjä tai kädessä pidettäviä laitteita tarvittaisiin. (Bolano, et al., 2020) 
<p>&nbsp;</p> 

### intelliRISK - Risk Aware Autonomous Robots 

Vuodesta 2017 saakka on Arne Rönnaun johtama tiimi tutkinut järjestelmää, jonka avulla robotit kykenevät tekemään itsenäisiä päätöksiä avaruusoperaatioissa. Projektissa käytetään FZI:ssä kehitettyä LAURON V (Legged Autonomous Robot Neural Controlled) robottia, joka pystyy liikkumaan turvallisesti jopa epätasaisessa maastossa. Tähän saakka työryhmät ovat päättäneet robotin toiminnoista perustuen robotilta saatuihin tietoihin. Nykyisessä järjestelmässä kaikkia robotin käytettävissä olevia tietoja ei siirretä työryhmälle, joten niitä ei voida ottaa huomioon päätöksenteossa. IntelliRISK-projektin tarkoitus on kehittää järjestelmä, jonka avulla voidaan arvioida riskejä ja vaikuttaa tilanteisiin itsenäisesti. Järjestelmän älykkyys on äärimmäisen tärkeää varsinkin työtehtävissä, joissa tehtävän onnistuminen on tärkeämpää kuin laitteistolle mahdollisesti aiheutuvat vahingot.  Haasteena ei ole vain ulkoisten vaarojen havaitseminen vaan myös robotin itsensä kuluminen.  Järjestelmän avulla robotti kykenee tunnistamaan, arvioimaan ja ottamaan tietoisia riskejä sekä ilmoittamaan aikeistaan valvontaryhmälle. Ollessaan tehtävänsä alussa robotti voi toimia varovaisesti, mutta ollessaan tehtäviensä lopussa se saattaa tehdä rohkeampia päätöksiä. Järjestelmää voidaan käyttää myös muualla kuin avaruusmatkoilla. Riskitietoisuutta voidaan tulevaisuudessa käyttää myös Industrial 4.0-sovelluksissa, jolloin ihmisten ja robottien yhteistyöstä saadaan turvallisempaa ja onnettomuuksia estettyä. Katastrofien torjunnassa ja niistä toipumisessa robotti voi laittaa ihmisen hyvinvoinnin omansa edelle, jotta pelastaminen olisi mahdollista myös vaikeissa olosuhteissa. Tehtävän onnistumisen kannalta tärkeintä on siis tietää mitkä riskeistä ovat suurimpia. (intelliRISK The odds..., n.d.)
<p>&nbsp;</p> 

### LAURON V Bio-Inspired Walking Robot 

Luonnosta inspiraation saaneen LAURON:in kehitys alkoi jo vuonna 1994. Robotti esiteltiin ensimmäisen kerran yleisölle CeBIT:ssä (Centrum der Büro- und Informationstechnik) Hannoverissa (Kuva  ). Tämän kuusijalkaisen Intian ruskosauvasirkan (Carausius morosus) muodon omaavan robotin tutkimus keskittyi aluksi itse kävelyprosessiin epätasaisessa ja vaikeassa maastossa. Ohjausohjelmistoa ja mekatroniikkaa on jatkuvasti paranneltu. (LAURON, n.d.)

![lauron](/assets/images/lauron.png)
##### LAURON I vuodelta 1994. (LAURON V, 2021) 
<p>&nbsp;</p> 

Vuonna 2013 valmistui nykyisen sukupolven LAURON V (Kuva  ), joka esiteltiin IEEE ICRA:ssa (International Conference on Robotics and Automation) Karlsruhessa. Nykyisen työn kohteena ovat luonnon inspiroima kävelyanalyysi, navigointistrategia, autonomia, eturaajojen manipulointi sekä energiatehokkuus. Robotin 6 alkaa on kiinnitetty keskusrunkoon sisäisellä alumiinirungolla, johon mahtuu kaikki tarvittava elektroniikka. Se on kooltaan 0.9 m x 0.8 m x 0.84 m (pituus x leveys x korkeus). Jokaisessa jalassa on 4 niveltä mikä mahdollistaa jalkojen taivutuksen eteenpäin. Se kykenee suoriutumaan esteistä, joiden kaltevuus on 25° ja säilyttämään tasapainonsa 43° kaltevuudella. Etujalkoja voidaan käyttää myös manipulaattoreina, jolloin varsinaista käsivarsitarttujaa ei tarvita. Jaloissa on 4 tehokasta DC-moottoria ja sen kokonaispaino on 42 kg. Hyötykuorma robotilla on 10 kg ja se mahdollistaa huipputason prosessorin ja tehtäväkohtaiset anturit. Siinä on sisäisiä antureita kuten mm. mittatilauksena valmistettujen moottoriohjaimien virtamittaus, jousitettujen jalkojen potentiometrit sekä erittäin tarkka IMU vartalon asennon havaitsemiseen. Pääsensoreina toimivat ”Pan-Tilt Unit”:iin kiinnitetyt kaksi korkean resoluution kameraa ja kinect. Laite tosin kykenee suuren kokonsa vuoksi kantamaan melkein minkä tahansa anturin, jota tarvitaan suoriutumaan tietystä tehtävästä. Päätä voidaan liikuttaa pituus- ja sivuttaiskallistuksella, jolloin LAURON:lla on 26 vapausastetta. Käyttäytymiseen perustuvan hallintajärjestelmän avulla robotti kykenee selviytymään muuttuvasta ympäristöstä ja odottamattomista tapahtumista kuten liukastuminen tai jokin este. (Heppner, et al., 2015) (LAURON, n.d) (He & Gao, 2020) 

![lauron](/assets/images/lauronV.png)
##### LAURON V (He & Gao, 2020)
<p>&nbsp;</p> 

PlexNav (Planetary Exploration and Navigation Framework) on hybridiarkkitehtuuri, jossa FZI:in oman MCA2 (Modular Controler Architecture) kehyksen mukana käytetään ROS:ia. ROS:in tarjoama julkaisija/tilaaja kommunikointityyli helpottaa suuresti erilaisten komponenttien integrointia järjestelmään, jopa ajon aikana.  (Heppner, et al., 2015) 

![lauron](/assets/images/PlexNav.png)
##### PlexNav arkkitehtuurin rakenne. (Heppner, & al., 2015)
<p>&nbsp;</p> 

PlexNav koostuu kolmesta kerroksesta (Kuva ), joista ensimmäinen kerros koostuu robottikohtaisesta toteutuksesta joka LAURON:in tapauksessa on käyttäytymisperusteinen hallinta. Tähän kuuluu jalan liikkeiden hallinta, anturin antaman tiedon tulkinta sekä turvallisuuden seuranta. Siihen sisältyy myös abstraktiokerros, joka paljastaa ROS-rajapinnat ylemmille kerroksille ja mahdollistaa turvallisen pääsyn matalan tason toimintoihin. Toinen kerros puolestaan koostuu robotin yksilöllisistä taidoista. PlexNav:in jokainen taito on komponentti, joka tarjoaa tietyn osajärjestelmän kuten manipulointi tai ympäristön kartoitus. Viimeinen taso hoitaa tehtävän kokonaisuuden. Se tarjoaa komponentit, jotka hallitsevat tehtävän tilaa ja kutsuu paljastuneet ominaisuudet taitotasolta. Kaikki tasot voivat käyttää tai julkaista maailmanlaajuisesti saatavilla olevia tietoja. (Heppner, et al., 2015) 
<p>&nbsp;</p> 

### ROBDEKON - Autonomous Handling of Hazardous Materials 

Ihmiset joutuvat työskentelemään terveydelle haitallisissa ympäristöissä käsitellessään myrkyllisiä jätteitä, puhdistaessaan kemiallisesti saastuneita alueita tai vanhoja kaatopaikkoja sekä suljettaessa ydinvoimaloita. He ovat tekemisissä epäpuhtauksien sekä tulipalo-, räjähdys- tai ydinsäteily vaaran kanssa. Heidän suojaamisensa edellyttää monimutkaisia ja usein raskaitakin suojatoimenpiteitä. ROBDEKON tulee sanoista: ”Robotersysteme für die Dekontamination in menschenfeindlichen Umgebungen”, ja se tarkoittaa vapaasti käännettynä vihamielisen ympäristön puhdistamista robottien avulla. Se on osaamiskeskus, joka on omistettu autonomisten ja puoliautonomisten robottijärjestelmien tutkimukselle. Keskus kehittää robotteja, jotka voivat suorittaa ihmiselle vaarallisia tehtäviä itsenäisesti, jolloin ihmiset voivat pysyä poissa vaara-alueelta. Vuoden 2018 kesäkuussa alkanut projekti on saanut BMBF:ltä 12 miljoonan euron rahoituksen siviiliturvallisuuden hyväksi. Alkuperäinen toiminta on suunniteltu jatkuvan vuoteen 2022, mutta tavoite toki on, että osaamiskeskuksen toiminta voisi jatkua vielä tämänkin jälkeen. Projektissa ovat mukana Fraunhofer Institute for Optronics, System Technology and Image Exploitation IOSB sekä näiden lisäksi Karksruhen teknillinen instituutti (KIT), Saksan tekoälyn tutkimuskeskus (DFKI) ja FZI:n tietojenkäsittelytieteen tutkimuskeskus. (ROBDEKON im Profil, n.d.) (ROBDEKON: Central Contact..., 2019) 

Tutkimuskohteita ovat mm. mobiilirobotit epätasaisessa maastossa, autonomiset rakennuslaitteet / koneet, manipulaattorien käyttö dekontaminaatioon, suunnittelualgoritmit, ympäristön monisensorinen 3D-kartoitus sekä teleoperointi VR:n avulla. Tekoälyn avulla robotit voivat suoriutua tehtävistä joko autonomisesti tai semiautonomisesti. Työ keskittyy aluksi kolmeen relevanttiin aihealueeseen: kaatopaikkojen ja pilaantuneiden alueiden kunnostamiseen, ydinlaitosten purkamiseen sekä laitoksen osien puhdistamiseen. (ROBDEKON im Profil, n.d.)  
<p>&nbsp;</p> 

### Human Brain Project - Event-based Vision with Spiking Neural Networks 

Euroopan komission rahoittaman tulevaisuuden ja kehittyvien teknologioiden (Future and Emerging Technologies, FET) lippulaivan ”Human Brain Project” (HBP) päätavoite on selvittää ihmisen aivojen toimintaa ja sitä mikä ”tekee meistä ihmisen”. Hankkeessa on mukana yli 120 instituutiota 24 eri maasta. Aivojen syvemmän ymmärtämisen saavuttamiseksi instituutiot tekevät yhteistyötä neurotieteellisen tiedon integroimiseksi käyttäen eri tieteenaloja kuten lääke-, informaatio ja tietotekniikka- (Information and Computer Technologies, ICT) sekä neurotiede. Nämä tulokset tulevat näyttämään tietä uusien aivosairauksien hoitoon ja uusien biologian inspiroimien teknologioiden kuten neuromorfisten laitteistojen ja ihmisen kaltaisesti käyttäytyvien robottien käyttämiseen. (The human brain..., n.d.)

FZI:stä mukana ovat tutkimusosastot IDS (Interaktive Diagnose und Servicesysteme) ja SE (Software Engineering) jotka keskittyivät projektin ensimmäisessä vaiheessa ohjelmistoinfrastruktuurin kehittämiseen tutkijoille sekä kehittäjille, jotta he voisivat luoda ja toteuttaa toistettavia neurorobottikokeita. Myöhemmissä vaiheissa projektissa keskityttiin teoreettisen neurotieteen inspiroimien robottitekniikoiden kehittämiseen. (The human brain..., n.d.) 

Neuro-Robotics-aliprojektin tavoite on tarjota tiedeyhteisölle yhtenäinen alusta, jolla suunnitella ja yhdistää teoreettisen neurotieteen periaatteet ja tiedot robottien realistisiin ja interaktiivisiin simulaatioihin. Tulokset voidaan helposti tutkia ja arvioida tietokantojen ja tietokonesimulaatioiden avulla (in silico). Alusta tarjoaa pääsyn laskentakeskusten korkean suorituskyvyn laskentaresursseihin ja erikoistuneisiin neuromorfisiin laitteistoarkkitehtuureihin, joiden avulla tutkijat voivat simuloida kokonaisia aivomalleja realistisesti ja yksityiskohtaisesti. (The human brain..., n.d.) 

Työn tuloksia ovat mm. järjestelmä, jolla ohjataan robottikättä (Schunk SVH) ihmisen lihaksista saaduilla signaaleilla, jotka on tallennettu ei-invasiivisella EMG-anturilla (Elektromyografia) joka on yleinen työkalu lääketieteessä ja biomekaniikassa Työssä keskityttiin yhden sormen aktivointiin anturista saaduilla ärsykkeillä. (Tieck, et al., 2018) (Tieck, et al., 2020). 

![human_brain](/assets/images/paakomponentit.png)
##### Pääkomponenttien konseptiarkkitehtuuri. (Tieck et al., 2018)
<p>&nbsp;</p> 
 
SNN:lla (Spiking Neural Network) luokiteltiin EMG-data ja laukaistiin liike refleksinä. Dataa saatiin tallentamalla ihmisen lihasten toimintaa Myo-liikkeentunnistimella (Kuva  ) , joka koostuu 8 tasavälein sijoitetusta lohkosta, joissa on 200 Hz näytetaajuuden omaavat EMG-anturit. (Tieck, et al., 2018) 

![human_brain](/assets/images/myo-liiketunnistin.png)
##### Myo-liikkeentunnistin ja 8 anturin aktiivisuus. (Tieck, et al., 2020)
<p>&nbsp;</p> 

Anturissa on indikaattori, jotta se voidaan sijoittaa aina samalla tavalla. Johdonmukaisen datan tallentamiseksi LED-valoilla varustettu segmentti on sijoitettava suunnilleen samaan asentoon. Pienillä vaihteluilla ei ole merkitystä koulutetun verkon käyttökelpoisuuteen. Raakojen sEMG-signaalien haku tapahtuu Python API:in avulla. Data muunnetaan piikeiksi ja signaalit luokitellaan, jotta aktiivinen sormi voidaan tunnistaa (Kuva  ). (Tieck, et al., 2018) 

![human_brain](/assets/images/datasetti.png)
##### Datasetti näyte 5 sormen harjoittelusta. Vasemmalta oikealle huiput kertovat sEMG:n aktivoitumisesta. (Tieck, et al., 2018)
<p>&nbsp;</p> 

Motorisen primitiivin avulla aktivointisignaalia käytetään laukaisemaan oskillaattori ja generoimaan liike. Tämän jälkeen primitiivillä kartoitetaan robotin kinematiikka ja piikit muunnetaan robotin moottorikomennoiksi (Kuva  ) Robotin käden ohjaamiseen käytetään virallista Schunk ROS-ajuria (Kuva  ). (Tieck, et al., 2018) 

![human_brain](/assets/images/arkkitehtuuri_sEMG.png)
##### Arkkitehtuuri sEMG-luokittelulla ja liikkeen aliverkoistoilla. Jokainen ympyrä edustaa piikkihermosolujen populaatiota. (Tieck et al., 2020)
<p>&nbsp;</p> 

Hermosolujen mallien luomiseen käytettiin NEF:ia (Neural Engineerin Framework) sekä Nengon ohjelmistopakettia. Ohjelmisto mahdollistaa laajojen SNN:ien luomisen hajottamalla verkot pienempiin osiin. Yhdistämällä kaikki erikseen optimoidut aliosat saadaan yksi suuri hermoverkko. (Tieck, et al., 2018) 
<p>&nbsp;</p> 


### SeRoNet - B2B Plattform for Service Robotics  

SeRoNet on 11:den tutkimus- ja teollisuuskumppanin verkosto, jota on vuodesta 2017 lähtien rahoittanut Saksan BMWi (Bundesministerium für Wirtschaft und Energie) n. 6.5 miljoonalla eurolla. Hankkeen on tarkoitus jatkua vuoden 2021 marraskuuhun saakka. (More cost-effective robot..., 2021) 

Palvelurobottien käyttöalueet ovat moninaiset ja niiden sovelluksia on laidasta laitaan kuten esim. logistiikassa, hoitotyössä, terveydenhuollossa ja kokoonpanon tuessa. Komponenttien yhteensopimattomuus ja epäselvät markkinat johtavat suhteettoman korkeisiin kustannuksiin tarvittavien ohjelmistojen ja laitteistojen kehittämisessä. SeRoNet kehittää avointa IT-alustaa palvelurobotiikan käyttäjille, järjestelmäpalvelujen tarjoajille sekä robotiikan ja komponenttien valmistajille.  Sen tavoite on vähentää ohjelmistojen kehitystyötä käyttäen modulaarisia, yhteistyöhön perustuvia ja kokoonpanolähtöisiä valmiita moduuleita. Alustan kautta järjestelmäintegraattorit voivat avata uusia markkinoita ja loppukäyttäjät voivat tarjota omia ohjelmistopalvelujaan muille yrityksille. Järjestelmien välisen yhteistyön perusta on mallipohjaisilla työkaluilla isOPCUA (Open Platform Communications Unified Architecture) (Kuva  ) (Buchholz, et al., 2018). (More cost-effective robot..., 2021) 

![seronet](/assets/images/SeRoNet.png)
##### SeRoNet ekosysteemi (Buchholz, et al., 2018) 
<p>&nbsp;</p> 

Robot.one ja xito.one sovellusalustalla laitteisto- ja ohjelmistovalmistajat voivat tulevaisuudessa kehittää komponentteja palvelurobotiikkaa varten ollen yhteydessä kaikkiin alan toimijoihin. Näin yritykset voivat verkostoitua ja työskennellä yhdessä ongelmien ratkaisemiseksi. (Buchholz, et al., 2018)
<p>&nbsp;</p> 


### CAD-2-PATH - Intuitive Robot Teach in 

Robotin liikkeiden ohjelmointi on usein monimutkaista ja aikaa vievää. 2018 Hannoverissa esiteltiin web-pohjainen CAD-2-PATH työkalu, jonka avulla 2D:ssä piirretty polku voidaan siirtää monimutkaisen komponentin kuten auton oven pinnalle. Polku on robotista riippumaton ja sitä voidaan säätää helposti suoraan tabletilta. Käyttäjä ”piirtää” 3D-malliin, joka luodaan työkappaleen CAD-tiedoista. (CAD-2-PATH: Intuitive..., n.d.) (Intuitive Creation of..., 2018

![cad-2-path](/assets/images/cad-2-path.png)
##### CAD-2-PATH piirretyn polun piirto (Max-Fax, 2018)
<p>&nbsp;</p> 

Teollisten ROS-rajapintojen avulla voidaan ajaa pitkin luotuja polkuja kevyellä robotilla, jonka adaptiivisen, voimaan perustuvan säätelyn ansioista myös epätasaiset ja voimakkaasti kaarevat pinnat voidaan työstää.  Innovaatio nopeuttaa erityisesti hitsauksen, purseenpoiston sekä liimauksen toteutuksissa.  Intuitiivisessa verkkosovelluksessa ei tarvita CAD-tietoa vaan polkuja voidaan luoda ja säätää suoraan tuotannossa. (CAD-2-PATH: Intuitive..., n.d.) (Intuitive Creation of..., 2018)
<p>&nbsp;</p> 

### VIPER

Golfauton kokoinen NASA:n kuumönkijä VIPER (Volaties Investigating Polar Exploration Rover) mobiilirobotin on suunniteltu laskeutuvan Kuun etelänavalle 2023 (Kuva  ). Sen tarkoitus on suorittaa 100 päivän työtehtävä, jossa se etsii vesijäätä ja muita potentiaalisia resursseja. Saatu tieto opettaa veden alkuperästä ja jakautumisesta kuussa ja auttaa määrittämään miten kuun resursseja saadaan ihmiskunnan tulevien avaruustutkimusten käyttöön. Ensimmäiset vesikartat merkitsevät kriittisiä askeleita NASA:n Artemis-ohjelmassa, jonka tarkoitus on luoda ihmiselle kestävät olosuhteet kuun pinnalle vuoteen 2028 mennessä. Aikaisemmista kuuta kiertävistä satelliiteista on saatu tietoa, että kuun pinnalla on vesijäätä. Jotta vesijäätä voidaan joskus hyödyntää, on VIPER:in vaellettava kuussa varusteinaan NSS (Neutron Spectrometer System), NIRVSS (Near-Infrared Volatiles Spectrometer System) sekä MSolo (Mass Spectrometer Observing Lunar Operations) ja kyettävä havaitsemaan, analysoimaan sekä suorittamaan metrin syvyisiä porauksia eri maaperistä, syvyyksistä ja lämpötiloista. Mönkijän on tarkoitus mennä pysyvästi varjoisiin kraattereihin, joissa vesijäävarastot ovat säilyneet miljoonia vuosia.  (Chen, 2020) (Chen, 2020)

![viper](/assets/images/viper.png)
##### VIPER liikkuvuustestissä. (NASA/Johnson Space Center, 2019)
<p>&nbsp;</p> 

Mönkijällä on edessään äärimmäisiä lämpötiloja ja sen laitteiston on kestettävä 260 °C vaihtelua auringonvalon ja varjon välillä. Akku, lämpöputket ja radiaattori auttavat estämään mönkijän osien jäätymisen tai ylikuumenemisen. Kuun ollessa paljon lähempänä maata kuin Mars, ei komentojen lähettämisessä mönkijälle ole paljoakaan viivettä. Marsin komennon viiveet ovat 10–20 minuutin luokkaa, kuuhun vie vain 6–10 sekuntia. Maan päällä olevat kuljettajat voivat siten käyttää VIPER:ia vuorovaikutteisesti. Koska tarkoitus on läpikäydä suuria alueita vaikeassa maastossa, ilman hyviä tiedustelukuvia kiertoradasta, antaa operaation tietokonesimulaatio mahdollisuuden harjoitella kriittistä operaatiota ennen käynnistystä. Kuun maaperästä ei ole täyttä varmuutta eikä siis ole tarkkaa tietoa siitä onko maaperää kovaa, pehmeää vai jotain siltä väliltä. Siksi mönkijä on suunniteltu ennennäkemättömän ketteräksi. Se voi ajaa sivuttain, vinottain, pyöriä ympyrää tai liikkua mihin tahansa muuttamatta katsanto suuntaa. Mikäli se joutuu pehmeään maastoon, kykenee se liikuttamaan renkaitaan kuin se kävelisi. Kuussa on äärimmäiset valon ja pimeyden vaihtelut, ja ne tuottavat erittäin pitkiä ja nopeasti liikkuvia varjoja. Aurinkoenergialla toimivan mönkijän on vetäydyttävä näistä varjoista ja etsittävä oikeanlaista aluetta samaan aikaan kun se ylläpitää yhteyttä maahan. Pimeä jakso voi olla jopa yhden viikon mittainen, jolloin mönkijän on pysähdyttävä tunnistettavaan turvapaikkaan, jonka pimeys kestää vain 4 päivää. Tämä tekee reittien suunnittelusta monimutkaista. Mönkijän suunnittelijoilla onkin aivan uusi haaste rakentaa valaistus – ja kamerajärjestelmä, joka toimii kuun ankarissa olosuhteissa. (Chen, 2020) 

Yhdessä mönkijältä saatujen tietojen kanssa MOC-tiimi (Mission Operations Center) käyttää NASA:n kehittämää verkkopohjaista tietojen visualisointialustaa nimeltä Open Mission Control Technologies. Open MCT-ohjelmisto on avointa lähdekoodia, joten se on vapaasti käytettävissä niin julkisen kuin yksityisen sektorin sovelluksissa. Tämä on yksi innovaatioista, joita VIPER tukee kehittyvässä avaruustaloudessa ja muualla, tarjoten näin kykynsä yritysten käyttöön. Ohjelmisto on jo lentänyt useilla NASA:n operatiivisilla missioilla ja se on tehty yhteistyössä NASA:n Pasadenassa Kaliforniassa sijaitsevan suihkumoottorilaboratorion Advanced Multi-Mission Operations System-järjestelmän kanssa. Yhteistyö teollisuuden kanssa vaikuttaa ohjelmiston käyttöjärjestelmän keskeisiin osa-alueisiin. Mukautetun koodin luomisen sijaan mönkijän lento- ja maanpintaohjelmistot käyttävät laajasti avoimen lähdekoodin ohjelmistoja kuten ROS 2. Kun tehtävä on ohi, VIPER-tiimin tarkoitus on julkaista mönkijän ohjelmisto vapaaseen käyttöön. Lähestymistapa mahdollistaa nopean, ketterän sekä kustannustehokkaan tavan kehittää mönkijän ohjelmistojärjestelmää, josta on hyötyä myös tulevaisuudessa. (Chen, 2021) 
<p>&nbsp;</p> 

### Näkövammaisten Smart Glass-älylasit 

Näkövammaisten on vaikeaa havaita lähellä olevia kohteita. Näkövammaisen valkoisen kepin avulla voi tunnustella vain pienen matkan päähän. Suresh, Arora, Laha, Gaba ja Bhambri ovat kehittäneet Smart Glass-älylasit, joiden avulla näkövammaisten elämänlaatua on mahdollista parantaa. Ne on tarkoitettu näkövammaisille, jotka eivät halua erottua muista apuvälineitä käyttäessään ja niille, joiden on tunnettava olonsa sosiaalisesti mukavaksi ja turvalliseksi itsenäisesti navigoidessaan. Älylasit koostuvat ultraääniantureista, joiden avulla edessä oleva kohde havaitaan reaaliajassa. Tieto syötetään Raspberryyn jossa analysoidaan onko kyseessä este vaiko henkilö. Tiedon avulla voidaan myös antaa tärinävaroitus kohteen suunnasta. Hätätilanteessa GSM-lisäominaisuus auttaa soittamaan apua. Koko järjestelmän ohjelmistokehystä hallitaan ROS:sin avulla. Se kehitettiin käyttäen ROS catkin työtilaa ja tarvittavia paketteja ja solmuja. ROS ladattiin Raspberry Pi:lle käyttäen Ubuntu Matea. (Suresh, et al., 2018) 

Laskelmien mukaan maailmassa on lähes 16,3 miljoonaa näkövammaista ja heidän määränsä on kasvussa (Kuva  ). (Suresh, et al., 2018) 

![smartglass](/assets/images/nakovammaisvaesto.png)
##### Näkövammaisväestö Pohjois-Amerikassa, Euroopassa ja Japanissa. (Suresh, et al., 2018)
<p>&nbsp;</p> 

Antamalla älylasien avulla näkövammaisille käsityksen ympäröivästä maailmasta he voivat elää helpompaa, terveempää ja onnellisempaa elämää. Lasien prototyyppi koostuu Raspberry Pi Zerosta, luujohtovärähdyksellisestä kuulokkeesta, 1080p 25 FPS HD kamerasta, 2500 mAh akusta, ultraäänietäisyysmittarista, värinänauhasta, GSM-, GPS-, Bluethoot-Wi-fi-moduulista. Kaikkien laitteiden on oltava kytkettynä toisiinsa, jotta kommunikointi tapahtuu ilman merkittäviä viiveitä. (Suresh, et al., 2018) 

![smartglass](/assets/images/toimintaperiaate.png)
##### Älylasien toimintaperiaate. (Suresh, et al., 2018)
<p>&nbsp;</p> 

Lasien suunnittelu tehtiin PTC Creolla ja CAD-malli (Computer Aided Design) tallennettiin STL-muotoon (Standard Triangle Language), jonka jälkeen se viipaloitiin Ultimaker Cura-ohjelmalla. Tulostimena toimi Ultimaker 2+ ja materiaaliksi valikoitui ABS (akryylinitriilibutadieenistyreeni). (Suresh, et al., 2018) 

Ultraäänianturien toiminta perustuu ääniaaltojen heijastumiseen. Etäisyys lasketaan kertomalla ääniaallon vastaanottamiseen kulunut aika ja äänen nopeus ja jakamalla saatu tulos kahdella. Aikaa tähän menee vain mikrosekunteja. Näkövammaisen molemmissa käsissä on värähtelynauha, jolla on yhteys Raspberry Pi:hin ja jotka värisevät ultraäänisensoreista saadun syötteen mukaan. Jokainen nauha koostuu kahdesta värähtelyliuskasta, joista yksi on edessä ja toinen takana. Mikäli esine tai este on henkilön edessä, värähtelevät molemmat käsien edessä olevat liuskat, kun taas jos esine on henkilön vasemmalla tai oikealla puolella värähtely tapahtuu kyseisellä puolella. Mikäli esine liikkuu kohti, antaa se varoituksen käyttäjän korvaan. (Suresh, et al., 2018) 

Toinen päälaitteiston komponenteista Raspberry Pi:in lisäksi on HD-kamera. Kamera toimii tuloanturina, joka ohjaa reaaliaikaisen syötteen Raspberrylle joka puolestaan laskee kaikki algoritmit sekä havaitsee ja tunnistaa ympäristön kohteet. Tunnistuksen jälkeen käyttäjälle annetaan palautetta ääntä käyttämällä. (Suresh, et al., 2018) 

Projektissa käytetään syväoppimista MobileNetsin ja Single Shot Detectorin kanssa. Resurssirajoitetuista laitteista kuten Raspberry Pi tai älypuhelin saadaan moduulit yhdistettäessä nopea reaaliaikainen tunnistus. (Suresh, et al., 2018) 

Syväoppimisen kolme ensisijaista menetelmää ovat: Faster R-CNNs, (YOLO) sekä Single Shot Detectors (SSDs). Projektissa käytetään viimeksi mainittua, sillä se on tasapainossa CNNn ja YOLOn välillä. Tämä siksi, että se sisältää kaikki laskennalliset tiedot yhdessä verkossa, jolloin kohteen tunnistuksen vaativaa järjestelmää on helppo kouluttaa ja integroida. (Suresh, et al., 2018) 

Käyttämällä MobileNetsiä vältetään perinteisten tapojen kuten ResNetin suuri koko (200–500 Mt). Perinteisen CNN:n ja MobileNetsin erona on MobileNetsiin sisällytetty syvyyssuuntaan erottuva konvoluutio. Konvoluutio jakautuu kahteen osaan: 3 * 3 syvyyskonvoluutio ja 1 * 1 pistekonvoluutio, joka vähentää verkon parametrien määrää, jolloin resurssitehokkuus säilyy. Arduinoon liitetyn GSM-, GPS- sekä puheentunnistusmoduulin avulla näkövammainen voi nopeasti hälyttää ennalta määrätyn kontaktin sekä ottaa yhteyttä hätäkeskukseen. Toteutusta aiotaan parantaa käyttämällä älypuhelinta, jolloin voidaan välttää GSM-, GPS- ja Raspberry Pi zero-moduulien käyttö. Käyttämällä jotain käytettävissä olevista alustoista kuten Google Assist, Siri, Cortana, Bixby tai Alexa voidaan äänikomennot toteuttaa edistyneemmin. Myös älylasien mallia ja kehystä aiotaan parantaa, jotta saavutetaan kompaktimpi muoto. (Suresh, et al., 2018) 
<p>&nbsp;</p> 

### Neuroverkon ja ROS:in käyttö uhkien havainnointiin ja partiontiin 

Kaupungistumisen, digitalisaation sekä lisääntyneen varallisuuden myötä väestön pakkaantuminen ostoskeskuksiin, teattereihin, huvipuistoihin yms. on lisääntynyt valtavasti. Robotiikka integroituna täydelliseen ohjelmistoarkkitehtuuriin mahdollistaa tehokkaan ratkaisun torjua joukkoteloitukset (vai lynkkaus?), terrorismi, taskuvarkaudet, varkaudet sekä sieppaukset (kidnappaukset?). Nykyiset sisätiloissa partioivat mobiilirobotit toimivat vain tarkkailukameroina, jotka liikkuvat ennalta määrätyillä alueilla tai ovat kauko-ohjattavia. Tämä järjestelmä ei kykene estämään rikollisuutta. (Maram, et al., 2019) 

Maramin, Vishnoin ja Pandeyn ohjelmistoarkkitehtuurin tavoitteena on kehittää robotti, joka kykenee tekemään älykkäitä päätöksiä konenäön avulla samalla kun se strategisoi liikkeitään tutustuessaan ympäristöönsä. ROS:in reitin suunnittelun, ympäristön havainnoinnin sekä neuroverkkojen avulla kehittäjien on mahdollista luoda robotti, joka jäljittelee ihmisen käyttäytymistä partioinnin aikana. Neuropohjaisen uhkien havaitsemispaketin tiedosto koostuu kuvista, jotka sisältävät aseita, räjähteitä ja esineitä, jotka voivat häiritä yleistä järjestystä. Käytetty tietoaineisto sisältää pistoolitietokannan, joka on saatu Soft Computing and Intelligent Information-järjestelmästä sekä Terravic Weapon Infrared-tietokannasta. Aineisto sisältää merkittyjä kuvia aseista ja räjähteistä. Riittävän kuvamateriaalin koonnin jälkeen data prosessoidaan käyttäen YOLO-arkkitehtuuria (Kuva   ). (Maram, et al., 2019) 

![uhat](/assets/images/YOLO.png)
##### YOLO arkkitehtuurin käyttö (Maram, et al., 2019)
<p>&nbsp;</p> 

Neuroverkon opetus perustuu esikäsittelyvaiheessa piirrettyihin rajauslaatikkoihin. Opetus voidaan suorittaa joko kolmannen osapuolen pilviympäristössä tai GPU:lla, joka kykenee käsittelemään tietoja. Tuloksena saadaan painotettu tiedosto joka ajettuna rinnakkain YOLO:n kanssa, antaa mahdollisuuden välittää kuvia tai kehyksiä ja saada tietoa yleistä järjestystä häiritsevistä esineistä. YOLO algoritmilla stressitestattiin myös muita kognitiivisia palveluita kuten Tensorflowta sekä Microsoft Vision:ia käyttäen julkisesti verkosta saatavilla olevaa videota. Kuvasta __ nähdään vertailun tuloksia. (Maram, et al., 2019)  

![uhat](/assets/images/stressitestit.png)
##### Stressitestien vertailutuloksia (Maram, et al., 2019)
<p>&nbsp;</p> 

Johtopäätös oli, että YOLO-algoritmi antoi tarkempia ja luotettavimpia ennusteita eri olosuhteissa. Joissakin olosuhteissa tarkkuus on saattanut kyseenalaistua, mutta nopeus on reaaliaikaisen ennustamisen päätavoite. Simulaatio toteutettiin käyttäen ROS yhteensopivaa Turtlebottia, mutta mukautettu robotti toteutettaisiin käyttämällä kooderi DC-moottoreita, Kinectiä, haluttua pyörämäärää sekä yhtä Adafruit-moottorin ohjainta. (Maram, et al., 2019) 

SLAM:in avulla robotti luo kartan ja lokalisoi itsensä käyttäen Adaptive Monte Carlo lokalisointialgoritmia. Koska Kinectia käytetään lähteenä, on tärkeää, että se muunnetaan vastaanottamaan data siten, että se on yhteensopiva ROS:in navigointipinon kanssa. Oletuksena ROS-kirjasto tarjoaa ros-perception paketin, jota kutsutaan ”pointcloud to laserscan”. Pointcloud-laserscan-solmu tilaa PointCloud-tiedot, jotka se julkaisee vastaavina Laser scan-tietoina. (Pitääks noi suomentaa?) Julkaisun jälkeen SLAM:ista vastuussa oleva gmapping-paketti tilaa tiedot odometri kalibroinnin perusteella ja liikuttaa robottia nähdäkseen kartan muodostumisen, joka voidaan nähdä RVIZ:ssa. Robotin käyttö ei rajoitu vain sisätiloihin vaan se voidaan mukauttaa myös ulkotiloihin, jolloin tutkimustuloksia voidaan käyttää estämään salametsästys ja tunkeutuminen sekä tarkistaa laittomat maahanmuuttajat. (Maram, et al., 2019) 



<p>&nbsp;</p>  
# Hankkeen onnistuminen

<p>&nbsp;</p>  
# Tulevaisuus

<p>&nbsp;</p>  
# Yhteenveto

<p>&nbsp;</p>  
# Lähdeluettelo










<!-- #### Header 4

*   This is an unordered list following a header.
*   This is an unordered list following a header.
*   This is an unordered list following a header.

##### Header 5

1.  This is an ordered list following a header.
2.  This is an ordered list following a header.
3.  This is an ordered list following a header.

###### Header 6

| head1        | head two          | three |
|:-------------|:------------------|:------|
| ok           | good swedish fish | nice  |
| out of stock | good and plenty   | nice  |
| ok           | good `oreos`      | hmm   |
| ok           | good `zoute` drop | yumm  |

### There's a horizontal rule below this.

* * *

### Here is an unordered list:

*   Item foo
*   Item bar
*   Item baz
*   Item zip

### And an ordered list:

1.  Item one
1.  Item two
1.  Item three
1.  Item four

### And a nested list:

- level 1 item
  - level 2 item
  - level 2 item
    - level 3 item
    - level 3 item
- level 1 item
  - level 2 item
  - level 2 item
  - level 2 item
- level 1 item
  - level 2 item
  - level 2 item
- level 1 item

### Small image

![Octocat](https://github.githubassets.com/images/icons/emoji/octocat.png)

### Large image

![Branching](https://guides.github.com/activities/hello-world/branching.png)


### Definition lists can be used with HTML syntax.

<dl>
<dt>Name</dt>
<dd>Godzilla</dd>
<dt>Born</dt>
<dd>1952</dd>
<dt>Birthplace</dt>
<dd>Japan</dd>
<dt>Color</dt>
<dd>Green</dd>
</dl>

```
Long, single-line code blocks should not wrap. They should horizontally scroll if they are too long. This line should be long enough to demonstrate this.
```

```
The final element.
``` -->
