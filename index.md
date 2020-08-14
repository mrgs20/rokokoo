---
layout: default
title: Rokokoo
description: Robotiikan koulutus kasvuyritysten ohjenuorana
---

<!-- Text can be **bold**, _italic_, or ~~strikethrough~~.

[Link to another page](./another-page.html).

There should be whitespace between paragraphs.

There should be whitespace between paragraphs. We recommend including a README, or a file with information about your project. -->

# Johdanto

Tähän sit jotain sopivaa tekstiä hankkeen loppuvaiheessa.


# Robot Operating System, ROS

Vuonna 2007 Stanfordin Artificial Intelligence laboratoriossa ja Willow Garagen avustuksella kehitetty Robot Operating System (ROS) edustaa avoimen lähdekoodin politiikkaa ja on siten muodostunut yhdeksi suosituimmista ohjelmistokehyksistä robotiikassa. GitHub-kehitysalustassa on yli tuhat ROS talletusta. ROS tukee mobiili-, teollisuus-, kirurgia- ja avaruusrobotiikkaa sekä autonomisia autoja. (Ohnsman, 2019) ROS on eräänlainen aarreaitta täynnä algoritmeja, ohjelmistoja, ajureita, toimintoja ja paljon muuta. ROS:sin joustavuus pohjautuu sen kykyyn toimia informatiivisena perustana innovatiiviselle kehitykselle. Muokattavuutensa vuoksi ROS mahdollistaa käyttäjien omien suunnittelumallien käytön. ROS:sin käyttö säästää tarvittavaa työvoimaa prosessiohjelmoinnissa sekä kehityskustannuksia erilaisten laitteisto- ja ohjelmistokirjastojen mahdollistaman viestinnän avulla.  Käyttäjäyhteisönsä jatkuvan kehittämisen ja lähdekoodin avoimuuden vuoksi ROS:sin käyttö koetaan turvallisena ja luotettavana. (Vozel, 2019) 

ROS markkinoiden odotetaan kasvavan vuoden 2019 321M $:sta 467M $:iin vuoteen 2024 mennessä (Taulukko  ). Sen vuotuinen CAGR (Compaund Annual Growth Rate) tällä aikajaksolla olisi täten 8.4%. Tutkimus- ja kehitystyöhön liittyvät teollisuus automaation varat, yhteistyössä toimivien modulaaristen robottien lisääntyvä käyttö sekä RaaS (Robotics-as-a-Service) kasvava kysyntä ennustavat edullisten ROS teollisuusrobottien käyttöönottoa. (Robot Operating System Market by Robot Type (Articulated, SCARA, Parallel, Cartesian, Collaborative), Industry (Automotive, Electrical and Electronics, Metals and Machinery, Food and Beverages, Healthcare), and Region - Global Forecast to 2024, 2019) 

![Taulukko](/assets/images/Taulukko_1.png)
##### ROS kasvuodotukset vuoteen 2024
<p>&nbsp;</p>  



## ROS 1


<p>&nbsp;</p>  
## ROS 2


<p>&nbsp;</p>  
### micro-ROS


<p>&nbsp;</p>  
### ROS + Matlab & Simulink


<p>&nbsp;</p>  
## ROS health


<p>&nbsp;</p>  
## ROS Industrial


<p>&nbsp;</p>  
### Liitännät muihin järjestelmiin


<p>&nbsp;</p>  
### MoveIt


<p>&nbsp;</p>  
### Gazebo


<p>&nbsp;</p>  
### Rviz


<p>&nbsp;</p>  
### Neuroverkot ja syväoppiminen


<p>&nbsp;</p>  
# Turvallisuus verkossa


<p>&nbsp;</p>  
# ROS tuettuja antureita

Erilaiset anturit kuuluvat jo melkein jokaisen arkeen. Antureilla mitataan lämpötilaa, etäisyyttä, ilman kosteutta, tasataan paineita ja havaitaan mahdollinen tulipalon aiheuttama savu tai häkä. Käyttökohteita ja tarkoituksia on lukemattomia. Anturit ovat laitteita, jotka mittaavat fyysistä syötettä ja muuntavat ne tiedoksi, jonka joko ihminen tai kone voi tulkita. ROS:sin avulla robotti kehittää tietoisuutta ympäristöstään käyttämällä esim. stereonäköä, inertiamittausta sekä 3D-laserskannausta. Robotti yhdistää keräämänsä tiedot, jotta se tietää missä se on, minne se on menossa tai mitä mahdollisia esteitä on matkalla. (A Case Study: Developing a ROS Robot with On-Board Computing for a University Robotics Department, 2020) Hyvä listaus ROS antureita löytyy ROS wiki sivistolta: http://wiki.ros.org/Sensors.  

## Velodyne Lidar (Velodyne)

Velodyne on 1983 perustettu yritys, joka tarjoaa tehokkaimpia ja älykkäimpiä markkinoilla olevia etäisyydenmittauslaitteita autonomiaan ja kuljettajan avustukseen. (Velodyne Lidar, Inc., n.d) Lidar (Light Detection and Ranging) kutsutaan usein myös laserskannaukseksi tai 3D-skannaukseksi. Lidar käyttää silmille turvallisia lasersäteitä muodostaakseen 3D-esityksen ympäristöstään. Se laskee etäisyyksiä lähettämällä laservalopulssin ympäristöönsä ja laskee ajan, joka pulssilta, kuluu heijastua kohteesta takaisin. Toistamalla prosessia miljoonia kertoja sekunnissa saadaan tarkka reaaliaikainen 3D kartta. Velodyne voidaan liittää ROS:iin ja generoida pilveen pistetietoja raakadatasta. (What is LIDAR?, 2020)  

![Kuva1](assets/images/Velodyne.png)
##### Velodyne simulointi Gazebolla
<p>&nbsp;</p>  
![Kuva2](/assets/images/Velodyne_Rviz.png)
##### Velodyne anturi visualisaatio Rviz:lla

## ZED 2 kamera (Stereolabs)

Stereolabs on markkinoiden johtava 3D-syvyys- ja liiketunnistusratkaisujen toimittaja. Heidän tuotteensa perustuu stereonäköön sekä tekoälyyn. ZED 2 on ensimmäinen stereo kamera, joka käyttää neuroverkkoa tuottaakseen ihmismäisen näkymän. Siinä on sisäänrakennettu IMU, barometri sekä magnetometri, joilla se kerää reaaliaikaista synkronoitua inertia-, korkeus- ja magneettikenttädataa. Alkuperäisillä 16:9 antureilla ja 8-elementteisillä äärimmäisen terävillä linsseillä, joissa vääristymä on optisesti korjattu ja joissa on laajempi f/1,8 aukko, voi tallentaa videon ja syvyyden jopa 120° näkökenttään 40 % suuremmalla valomäärällä. (Built for the Spatial AI era, 2020) 

![Kuva3](/assets/images/ZED_2.png)
##### ZED 2 visualisaatio Rviz:llä

<p>&nbsp;</p>  
## TeraRanger (Terabee)

Terabee perustettiin vuonna 2012 tarjoamaan innovatiivista dronepalvelua erityisen vaativiin tarkastuksiin. Vuonna 2013 näki European Centre of Nuclear Research (CERN) mahdollisen potentiaalin ja tiedusteli, kykenisivätkö he kehittämään täysin autonomimisen dronen tutkimaan Large Hardon Colloder (LHC) tunnelia, joka on maailman suurin ja tehokkain hiukkaskiihdytin. Markkinoilla huomattiin olevan aukko ja nykyisin Terabee kehittää ja valmistaa monia erilaisia anturimoduleja kuten 2D-infrapuna LED Time-of-Flight (ToF) etäisyysantureita, 3D ToF syvyys- ja lämpökameroita. (About us, n.d) (The Large Hadron Collider, 2020) Esimerkkinä mainittakoon TeraRanger Evo 60 m (Kuva  ), joka kuuluu TeraRanger tuoteperheeseen. Se on pieni ja kevyt, pitkän kantaman ToF- anturi, joka tarjoaa kalibroidut etäisyyslukemat millimetreinä ja käyttää LED teknologiaa laserin sijaan. (teraranger, 2019)  

![Kuva4](/assets/images/TeraRanger.png)
##### TeraRanger Evo 60 m 

<p>&nbsp;</p>  
## Xsense MTi IMU (Xsens)

Xsens on vuonna 2000 perustettu innovaatiojohtaja 3D-liikkeenseuranta- ja tallennusteknologiassa. Kuten nimikin sanoo perustuvat inertia-anturit inertiaan eli hitausmomenttiin. Ne vaihtelevat MEMS-inertia-antureiden muutaman neliömillin kokoisista erittäin tarkkoihin rengaslasergyroskooppeihin, joiden halkaisija saattaa olla jopa 50 cm kokoinen (Kuva  ). Inertial Measurement Unit (IMU) on muista riippumaton järjestelmä, joka mittaa lineaarista ja angulaarista liikettä kolmen gyroskoopin ja kiihtyvyysmittarin avulla. (About us, n.d) (Inertial Sensor Modules, n.d) 

![Kuva5](/assets/images/Xsens.png)
##### Xsens MTi

<p>&nbsp;</p>  
## Hokuyo Laser (Hokuyo)

Intel® RealSense™ D400-sarjan syvyyskamerat käyttävät stereonäkymää laskeakseen syvyyden. Stereokuva toteutetaan käyttämällä vasenta ja oikeaa kuvanninta sekä valinnaista infrapunaprojektoria. Matala tekstuurisissa näkymissä infrapunaprojektori heijastaa näkymätöntä staattista IR (Infrared) kuvioita parantaakseen syvyystarkkuutta. Kuvantimet tallentavat näkymän ja lähettävät datan syvyysnäköprosessorille, joka laskee kuvan jokaiselle pikselille syvyysarvot korreloimalla pisteitä keskenään ja siirtämällä pisteitä kuvien välillä. Syvyyspikseliarvot prosessoidaan syvyyskehyksen luomiseksi. Perättäisistä syvyyskehyksistä saadaan luotua syvyysvideostriimaus (Kuva  ). (Intel® RealSenseTM Product Family D400 Series, 2020) 

![Kuva6](/assets/images/Intel_Realsense.png)
##### Aktiivinen IR Stereonäkö teknologia

<p>&nbsp;</p>  
# Alustat

Alustoja käytetään sovellusten, prosessien sekä teknologioiden kehittämisen pohjana. Valintaan vaikuttaa käyttötarkoituksen lisäksi moni seikka, kuten mm. tulo/lähtöjärjestelmät, rajapinnat, haluttu prosessorin nopeus, muistikapasiteetti sekä laajennusmahdollisuudet. Myös kaikki x86-arkkitehtuurin prosessorit ovat käytettävissä. Tässä mainitaan vain muutama soveltuva alusta. 

### NVIDIA TX1/TX2

NVIDIA® Jetson™- järjestelmät nopeampaan autonomisten koneiden ohjelmistojen ajamiseen pienemmällä virrankulutuksella. Jokainen on kokonainen SOM-järjestelmä (System-on-Module), jossa on CPU (Central Processing Unit), GPU (Graphics Processing Unit), PMIC (Power Management Integrated Circuit), DRAM (Dynamic Random Access Memory) ja flash-muisti. Jetson on laajennettavissa valitsemalla sovellukselle sopivia SOM ja rakentamalla kustomoitu järjestelmä vastaamaan erityistarpeista. (Embedded Systems for Next-Generation Autonomous Machines, 2020) 

### Raspberry Pi 4

Viimeisin Raspberry Pi 4 Model B tarjoaa suorityskyvyn, joka on verrattavissa x86 pöytäkoneeseen. 64-bittinen neliydinprosessori, kahden näytön tuki 4K:n resoluutiolla mikro-HDMI porttiparin kautta, jopa 8 GB RAM-muistia, kaksitaajuinen 2.4 / 5 GHz langaton LAN (Local Area Network), 5.0 Bluetooth, Gigabitin Ethernet, USB 3 ja PoE (Power over Ethernet) ominaisuus erillisen lisäosan kautta. (Raspberry Pi 4 Model B, 2020) 

### Intel NUC

Intel® NUC (Next Unit of Computing) on pienikokoinen pöytäkone, joka tarjoaa suorituskykyä Celeronista Core i7:ään. Ensimmäiset laitteet tuotiin markkinoille 2013. Ytimenä toimii NUC Board emolevy, jossa on sisäänrakennettu suoritin. Intel HD tai Iris Graphics näytönohjain taas puolestaan on integroitu suorittimeen. Tehomalleissa on lisäksi integroitu Radeon RX Vega näytönohjain. Uusimmat NUC:it käyttävät DDR4 SO-DIMM muistimoduuleita 2400 MHz muistinopeuksilla. Ne tukevat kahden muistimoduulin käyttöä Dual Channel tilassa parantaen näin suorituskykyä. SSD kiintolevyjä on saatavilla 2.5” SSD ja M.2 SSD. Intel NUC tukee sekä Windows 10 käyttöjärjestelmää että Linuxia. Ubuntulla ja siihen perustuvilla jakeluilla kuten esim. Mint on paras Intel NUC tuki. Molemmat käyttöjärjestelmät voidaan asentaa myös rinnakkain nk. Dual-boot tilaan. (Intel NUC Ostajan Opas 2019, 2020) 

### Odroid-XU4

Odroid-XU4 on yhden piirilevyn tietokone. Siinä on Samsung Exynos 5422 (4x Cortex-A15 @ 2.0GHz ja 4x Cortex-A7 @ 1.4GHz) suoritin, yhdistettynä Mali-T628 MP6 GPU ja 2 Gt RAM-muistiin. Se voi suorittaa Ubuntun ja Androidin uusimpia versioita. Ordroid-XU4:llä on erittäin suuri tiedonsiirtonopeus. Miinuspuolena voidaan mainita, että siitä puuttuu Wifi- tai Bluetooth yhteys, jotka ovat saatavana vain USB-dongleina. (2020 Best Single Board Computers/ Raspberry Pi Alternatives, 2020) 

<p>&nbsp;</p>  
# ROS:sin hyödyntäminen

Älykkäiden robottien suunnittelu ja rakentaminen ei ole niin yksinkertaista ja suoraviivaista kuin se voisi olla. Monet robotiikassa työskentelevät joutuivat usein aloittamaan aivan alusta aloittaessaan uuden projektin ja uudelleen kehittää ohjelmistoinfrastruktuurin joihin robottien algoritmit perustuvat. Jaetut työkalut ja resurssit olivat vähissä. ROS:sin etu on siinä, että suurimmassa osassa tapauksia ohjelmiston on jo todettu toimivan käytännössä. (Mok, 2020)

## Case-esimerkkejä maailmalta



### Teollisuusrobotit

ISO 8373:2012 mukaan teollisuusrobotti on autonomisesti ohjautuva, uudelleen ohjelmoitavissa oleva, moneen tarkoitukseen sopiva kolme tai useampi akselinen manipulaattori, joka voidaan asentaa joko kiinteästi tai käyttää mobiilina teollisuuden automaatiosovelluksissa. Näitä ovat mm. lineaari-, SCARA-, delta-, ja nivelrobotit. (Mueller, 2019) Koneoppiminen, AI (Artificial Intelligence), IIoT (Industrial Internet of Things) sekä ihmisen ja koneen yhteistyö sekä autonomiset mobiilijärjestelmät ovat tätä päivää. Edessä on kuitenkin suuria haasteita, kuten nopeasti muuttuvat kuluttajasuuntaukset, resurssien puute, ammattitaitoisten työtekijöiden puute, ikääntyvä yhteiskunta ja paikallisten tuotteiden kysyntä. Joustava teollisuusrobotiikka mahdollistaa ratkaisun näihin haasteisiin. (World Robotics 2020, 2020) 

### MotoPlus ™ SDK ohjain 

Japanilainen Yaskawa Motoman oli yksi ensimmäisistä yhteistyö-, ja teollisuusrobottien valmistajista, joka hyödyntää ROS:sia. Yaskawa:lla on ROS-I ajuri YRC1000, YRC1000micro, DX200 ja DX100 robottien ohjaimiin. Ohjain kehitettiin käyttämällä MotoPlus™ SDK:ta (Kuva  ). Se sisältää C/C++ yhteensopivan ohjelmointirajapinnan (API, Application Programming Interface) jolla ohjelmoijat voivat tehdä reaaliaikaisia sovelluksia, jotka toimivat robotin alkuperäisessä VxWorks-käyttöjärjestelmässä. Rajoitettujen sovellusten kehittäminen voimanhallintaan, visuaaliseen robotin ohjaukseen sekä geneeriseen anturien integrointiin mahdollistuu. (Specific Unified Robot Description Formats (URDF) on saatavana robottien käsivarsien simulointiin. (Vozel, 2019) 

![Kuva7](/assets/images/Liikepaketin_kerrostumat.png)
##### Ros-Industrial liikepaketin kerrostumat sekä miten MotoROS ja Yaskawa Motoman ohjain liittyvät toisiinsa

<p>&nbsp;</p>  
### Plug’n’play ROS-ohjain 

Tanskalainen Universal Robots on hallitseva kevyiden käsivarsirobottien toimittaja sekä teollisuuteen että tutkimukseen ja opetukseen. Tutkimuskenttä on kehittänyt kolmansien osapuolien ohjaimia, joilla ROS yhteisö on voinut kommunikoida UR robottien kanssa. ROS yhteisöstä löytyy yli 200 haaraa, jotka ovat UR yhteensopivia. UR ei silti koskaan ole ollut kehittämässä tai tukemassa näitä ohjaimia. Saatavilla on monia yhteisön kehittämiä ohjaimia, joista ei tiedä millä niistä on viimeisimmät ominaisuudet tai mitkä niistä tukevat oikeaa UR ohjelmaversiota. (Madsen, 2019) 

Jotta Universal Robots: in parhaita ominaisuuksia hyödynnettäisiin, kehittivät he yhteistyössä saksalaisen tutkimuslaitoksen, FZI (Forschungszentrum Informatik, Research Center for Information Technology) kanssa Universal Robots: in tukeman ROS-ohjaimen, jotta siitä saatiin vakaa ja kestävä. Ohjain julkaistiin markkinoille lokakuussa 2019. Tämä on ”plug’n’play”-tyylinen, helppokäyttöinen ohjain UR roboteille. Se hyödyntää robotin pääominaisuuksia, jotta se kykenee parhaaseen suorituskykykyynsä ja tarjoaa parhaimman teollisuusluokan rajapinnan, jonka nykyinen ROS käytäntö mahdollistaa. Ohjain sisältää spesifit robotin kalibrointidatat parhaaseen tarkkuuteen. Ohjain tulee olemaan avoin lähdekoodi ja nojaa tulevaisuuden yhteisökehitykseen. Ohjain on tarkoitettu CB3 ja e-sarjalaisille, joissa RTDE (Real-Time Data Exhange) on saatavilla (Kuva  ). (Madsen, 2019; Universal Robots ROS driver, 2020) 

![Kuva8](/assets/images/Universal.png)
##### Universal robots:in e-sarjalaiset

<p>&nbsp;</p>  
### ROSweld hitsausjärjestelmä

Norjalainen robottijärjestelmien integraattori, PPM Robotics on kehittänyt ROSweldin (Kuva  ) joka on ensimmäinen raskasrobottihitsausjärjestelmä jossa käytetään koneoppimista monipalkohitsauksen suunnittelussa ja mallinnuksessa. ROSweldiin kuuluu myös suunnittelu CAD-malleista, graafinen monipalkohitsauksen poikkileikkauksen käsittely, simulointi sekä hitsauskameran integraatio. Konenäköjärjestelmä käyttää FlexGui 4.0:aa käyttöliittymänä, jolla voidaan uudelleenohjelmoida työstettävät kappaleet, filtteri, parametrit sekä toistot. ROS-alustasta johtuen näköjärjestelmä on robotti ja kamera riippumaton. (Santos, 2020) 

![Kuva9](/assets/images/ROSweld.png)
##### ROSweld järjestelmä PPM Robotics:lta

<p>&nbsp;</p>  
ROSweld järjestelmässä jokainen komponentti on solmu tarjoten saman toiminnallisuuden ohjainryhmässä. Eri moduuleille on vakaa viestintäkerros ja standardit. MoveIt!, Rviz, RobotWebTools ROS2d.js, PCL (Point Cloud Library), pyros sekä rosbridge ovat käytössä olevia komponentteja. (Thomessen, 2018) 

![Kuva10](/assets/images/ROSweld_järjestelmä.png)
##### Järjestelmän rakenne

<p>&nbsp;</p>  
### Autonomiset ajoneuvot

Määritelmän mukaan ajoneuvo, joka havainnoi ja tunnistaa ympäristönsä sekä kykenee toimimaan itsenäisesti, luokitellaan autonomiseksi (Kuva  ). Autonomisten ajoneuvojen haasteita ovat ja tulevat edelleen olemaan lokalisointi, kartoitus, näkymän havainnointi, ajoneuvon hallinta, liikeradan optimointi sekä korkeatasoiset ennakoivat päätökset. (Fridman, ym., 2017) Volvo Car Group:in teknologiajohtaja Henrik Green:in mukaan täysin autonomisilla ajoneuvoilla on potentiaalia parantaa liikenneturvallisuutta tasoon, jota ei ole aiemmin nähty ja mullistaa tapa, jolla ihmiset elävät, työskentelevät ja matkustavat. (Cuneo, 2020) 

![Kuva11](/assets/images/Autonomisen auton komp.png)
##### Autonomisen auton tärkeitä komponenetteja

<p>&nbsp;</p>  
### Autonominen kuorma-auto

Yhdysvaltalainen Embark on vuonna 2016 perustettu kahden nuoren kanadalaisen tietokone tutkijan startup San Franciscossa. Yritys toimii yhteistyössä Electroluxin ja Ryderin kanssa ja kehittää autonomisten kuorma-autojen (Kuva  ) teknologiaa, jossa kuorma-autot kulkevat maanteillä ilman kuljettajaa, täysin itsenäisesti jopa 1046 km matkan (Sushant, 2019). Heidän kokonaisrahoituksensa on 117M $, josta 70M $ tuli vuonna 2019. (Ohnsman, 2019) Erilaisia tutkia, kameroita ja syvyysantureita, kuten LiDAR:ia (Light Detection and Ranging) käyttämällä miljoonat saadut datapisteet käsitellään neuroverkolla, Deep Neural Nets (DNN). Näin kuorma-auto kykenee oppimaan kokemuksistaan kuten ihmisetkin. Terabittejä reaalimaailman dataa analysoituaan neuroverkko oppii itsenäisesti tunnistamaan häikäisyn, sumun ja pimeyden. (Fleet Owner, 2017) Embark Trucks toimii nykyisin tason kaksi autonomiana. Tämä tarkoittaa sitä, että ammattitaitoisen kuljettajan on lain mukaan istuttava ohjauspyörän takana varmistuksena. Erikoisvalmisteinen kaksoisredundantti tietokone, joka testaa itsensä satoja kertoja sekunnissa tarkkailee jokaista komentoa reaaliajassa. (Sushant, 2019) 

![Kuva12](/assets/images/Autonominen kuorma-auto.png)
##### Embark kuorma-auto

<p>&nbsp;</p>  
### Autonomisten autojen Rosbag-data

Yhdysvaltalainen Ford Motor Company on vuonna 1903 perustettu yhtiö, joka on valmistanut T-mallin, Continentalin, Mustangin ja Broncon. He ovat valmistaneet myös lentokoneita, radioita, jääkaappeja, postituskoneita sekä sääsatelliitteja. Maaliskuussa 2020 Ford julkisti kaikessa hiljaisuudessa kokoelman, joka sisältää useiden eri autonomisten autojen datan – Ford Autonomous Vehicle Dataset. Data on kerätty eri päivinä ja aikoina vuosina 2017-2018. Ajoneuvot kulkivat keskimäärin 66 km: n reitin ja jokaisessa oli Applanix POS-LV GNSS- järjestelmä, neljä HDL-32E Velodyne 3D-lidar skanneria, kuusi 1,3 MP harmaapiste kameraa katolle asennettuna 360 asteen peittoa varten ja yksi 5 MP: n harmaapiste kamera tuulilasin taakse asennettuna suoraan eteenpäin kohdistuvan näkymän varmistamiseksi. Auton takaluukkuun sijoitettiin neljä Quad -core i7-prosessoria, joissa oli 16 Gt RAM, verkkolaitteet ja jäähdytysmekanismi. Aineiston jälkikäsittely suoritettiin kannettavalla Dell Precision 7710 tietokoneella. Kaikki tieto on saatavissa Rosbag-muodossa (Kuva  ), jota voidaan visualisoida ja muokata ROS:sin avulla. He toivovat, että tämä monen vuodenajan aineisto tulisi olemaan hyödyllinen robotiikalle ja AI-yhteisölle sekä tarjoamaan uusia tutkimusmahdollisuuksia. (Wiggers, 2020) 

![Kuva13](/assets/images/Rosbag.png)
##### Yhteenveto Rosbag-viesteistä

<p>&nbsp;</p>  
## Autonomiset mobiilirobotit (AMRs, Autonomous Mobile Robots)

Mobiilirobotteja käytetään teollisuudessa, kotitalouksissa ja erilaisissa palvelutoiminnoissa. Ne ovat tunnettuja uniikista kyvystään navigoida kontrolloimattomassa ympäristössä sensoreiden, piirustusten, tekoälyn, 3D- tai 2D-näön tai vastaavan kautta. ”AMR: t eivät vain kulje paikasta A paikkaan B, vaan niiden havaintokyky sallii uudelleenreitityksen, mikäli jokin este tulee niiden eteen.” sanoo Matt Wicks, tuotekehityksen varajohtaja Honeywell Intelligent: sta. (Zenner, 2019) 

### Relay-palvelurobotti

Yhdysvaltalainen Savioke on vuonna 2013 perustettu yritys, joka kehittää ja valmistaa autonomisia palvelurobotteja. Sen lippulaiva on Relay niminen robotti (Kuva   ), joka käyttää sisäistä karttaa ja LiDar:ia liikkuakseen ihmisten parissa. Suomalainen hissivalmistaja KONE tekee Savioke:n kanssa yhteistyötä huippuluokan hotelleissa. Tulevaisuudessa hotelleissa ei tarvitse olla mitään ylimääräisiä asennuksia sillä Relay ja hissit tulevat käyttämään KONE:een Flow Connectivity- ja pilvipalveluita, jolloin Relay kommunikoi KONE:een IoT alustan kanssa. (The robot butler is coming to a hotel near you, 2018) Yhtiö sai vuonna 2018 13.4M $ rahoituksen laajentaakseen tuotteensa sairaaloihin, joissa Relay voi auttaa sairaanhoitajia, laboratorioteknikoita ja muita terveydenhuollon ammattilaisia toimittamalla esim. näytteitä, lääkkeitä ja tarvikkeita. (Johnson, 2018)  

![Kuva14](/assets/images/Relay.png)
##### Savioke, Relay

<p>&nbsp;</p>  
### Moxi-mobiilirobotti manipulaattorilla

Yhdysvaltalainen Diligent Robotics perustettiin vuonna 2017 sosiaalisen robottiteollisuuden asiantuntijoiden toimesta. He ovat luoneet Moxi-mobiilirobotin, jossa on manipulaattori ja johon yhdistyy sosiaalinen älykkyys sekä ihmisohjatut oppimismahdollisuudet. Moxi toimii sairaaloissa auttaen hoitajia ei-potilas-hoidollisissa tilanteissa, jolloin hoitajille jää enemmän aikaa itse potilaiden hoitoon. Näitä tehtäviä ovat mm. tarvikkeiden kerääminen, potilaslaboratorionäytteiden ja päivittäisten liinanvaatteiden toimittaminen sekä esineiden hakeminen keskusvarastosta. Moxi parantaa tehokkuutta, lisää työntekijöiden tyytyväisyyttä sekä parantaa hoidon laatua. Robotti käyttää koneoppimista kohteiden tunnistukseen ja tarttumiseen sekä ROS:iin perustuvaa navigaatio-ohjelmistoa. Siinä on osia eri laitevalmistajilta kuten Fetch Robotics, Velodyne Lidar, Intel, Kinova ja Robotiq. (Kara, 2020) (Diligent Robotics transforming the meaning of "work", n.d) 

![Kuva15](/assets/images/Moxi.png)
##### Moxi-mobiilirobotti manipulaattorilla

<p>&nbsp;</p>  
### Windows IoT tuki Jackal UGV:lle

Kanadalainen Cleatpath Robotics on neljän yliopistokaveruksen kellarista vuonna 2009 ponnistanut, palkittu, johtava miehittämättömien robottiajoneuvojen valmistaja maailmalla. Heidän tuotteitaan käytetään maataloudessa, kaivostoiminnassa, teollisuudessa, asevoimissa ja eri tutkimusaloilla. Toukokuussa 2020 Clearpath ilmoitti aloittavansa Windows IoT Enterprise tuennan, alkaen Jackal UGV:sta. Jackal (Kuva  ) on pieni, kestävä mobiilirobotti, jota voidaan käyttää ympäristön etävalvonnassa ja -tarkastuksissa tilanteissa, jotka vaativat navigointia ulkona ja/tai ihmisen ja robotin vuorovaikutusta. Siinä on sisäänrakennettu tietokone, GPS (Global Positioning System) sekä IMU (Inertial Measurement Unit) joka on integroitu ROS:iin käyttövalmiin autonomian vuoksi. Se on valmistettu tukevasta alumiinirungosta, siinä on suuri vääntömomentti 4 x 4 voimansiirrolla tehden siitä soveltuvan vaikeisiinkin maasto-olosuhteisiin. Siinä on IP62 luokituksen omaava kotelo ja sen kykenee operoimaan -20°C - 45°C lämpötiloissa. (Jackal, n.d) (Clearpath robots on Windows 10, 2020)

Windows 10 Enterprise tuo mukanaan hyötyjä kuten yritysluokan suojauksen, helpon yhdistettävyyden pilveen, enemmän älykkyyttä Windows:in ML ROS noden kautta sekä nopeamman kehityksen. (Clearpath robots on Windows 10, 2020)    

![Kuva16](/assets/images/Clearpath Robots, JACKAL.png)
##### Clearpath Robots, JACKAL

<p>&nbsp;</p>  
# ROS Suomessa

### Ohjelmistokehitys

VAISTO on Tampereella sijaitseva yritys, joka tekee yhteistyötä älykytkettyihin ajoneuvoihin, koneisiin ja teollisuusautomaatioon erikoistuneiden yritysten kanssa. Heidän tavoitteensa on auttaa asiakkaitaan kehittämään parempia tuotteita sekä kokemuksia teollisuuden AI:n avulla hyödyntämällä datapohjaista tekniikkaa. Yrityksen ytimenä toimii ohjelmistokeskeisyys. (What Vaisto can do for you., n.d) Vaistossa käytetään ROS:sia autonomisten työkiertokonseptien prototyyppinä. Vaisto myös kehittää reaaliaikaisia datavirtoja autonomisille hallinta järjestelmille. (Koning, n.d) 

### Autonominen kuljetus

Sensible 4 on Espoossa sijaitseva palkittu start-up joka suunnittelee ja kehittää autonomisia ajoneuvoja erilaisiin sääolosuhteisiin jotta kaupungeista voidaan saada puhtaampia ja täten ihmiskunnalle kestävämpi tulevaisuus. He ovat luoneet uraauurtavan ja ainutlaatuisen tekniikan itseohjautuville ajoneuvoille. Heidän tavoitteensa on, että vuonna 2021 näitä itseohjautuvia linja-autoja (Kuva   ) olisi osana kaupunkien nykyisiä kuljetusjärjestelmiä. (Steering towards a smarter planet, 2019) NordicNinja VC rahoitti ensimmäisen rahoituskierroksen 100M $ jota tukivat japanilaiset teknologiayritykset ja ITOCHU, joka on yksi suurimmista japanilaisista kauppayhtiöistä. Alkuvuonna 2020 Sensible 4 keräsi 7M $ joiden odotetaan laajentavan yritysmarkkinoita Eurooppaan ja Aasiaan. (Finnish Sensible 4 raises $7 million to support expansion of autonomous driving system specialised for harsh weather conditions, 2020) 

![Kuva17](/assets/images/Gacha bussi.png)
##### Gacha, autonominen linja-auto

<p>&nbsp;</p>  
LiDAR-pohjainen paikannusohjelmisto suodattaa poikkeukset kuten lumen, sateen tai sumun, sallien näin etenemisen ilman kaista- tai maamerkkejä. Jotta saavutetaan todella tarkka paikannus olosuhteista riippumatta, käytetään omaa 3D-kartoitusta ja karttapohjaista lokalisointialgoritmia. LiDAR:in antamista 3D-tiedoista luodaan ympäristökartta, mutta sen sijaan, että käytettäisiin raakaa valotutkan antamaa dataa tai tunnistettaisiin datan antamat fyysiset piirteet, esitetään ympäristö nk. ”tilastomatemaattisena tilavuusjakautumana”. Erilaisia antureita käyttämällä havaitaan ja tunnistetaan esteet jopa näkyvyyden ollessa heikko. Esteiden havaitseminen perustuu monimuotoantureiden dataan ja omaan paikannusjärjestelmään, joka antaa sekä ajoneuvon tarkan sijainnin että 3D-mallin ympäristöstä. Havaitut esteet luokitellaan syväoppimisen avulla omiin kategorioihinsa sijainnin, koon tai nopeuden mukaan samalla ennustaen tulevan liikkeen. Lopuksi havainnot integroidaan monikohdeliikenteenseurantaan tarjoten näin parhaan mahdollisen tilannetietoisuusennusteen ohjausjärjestelmälle. (Our autonomous driving software, 2019) 

MPC-pohjaista (Model Predictive Control) liikerataohjausta käytetään optimoimaan ajoneuvojen ohjaustoimintoja suhteessa liikeratapisteiden sekvenssiin. Näin voidaan ennustaa ajoneuvon liikkuminen muutamia sekunteja etukäteen. S4 sijaintipino tarjoaa automaattisen kulkukelpoisuusindeksikartan. Näin ajoneuvo voi poiketa reitistä tarpeen tullen. Tieolosuhteet havaitaan reaaliajassa. (Our autonomous driving software, 2019) 

Tällä hetkellä SAE-tason 4 automaatiojärjestelmä tarvitsee ihmistä varmistukseksi. Järjestelmä sisältääkin ohjaus- ja valvontajärjestelmän antaen etäkäyttäjälle reaaliaikaista tietoa ajoneuvon tilasta ja sijainnista. (Our autonomous driving software, 2019) 

<p>&nbsp;</p>  
### Ûber-drone sekä autonomiset ajoneuvot

Fleetonomy.ai Oy on vuonna 2016 perustettu osakeyhtiö, jonka kotipaikka on Helsinki. He tekevät yhteistyötä kumppanien kanssa hankkeissa, jotka voivat muuttaa maailmaa sellaiseksi joka useimmille on vielä science fictionia. (Fleetonomy.ai Oy, n.d) (Fortum GO, n.d) Yhtiön toimitusjohtajan Markus Kantosen (Kantonen, Toimitusjohtaja, 2020) (muuta tää lähdejuttu oikein, kun valmista!) mukaan monen UAV:in ja UGV:in komentorajapinta laitteen puolesta on toteutettu ROS:illa. Laitekohtaiseen komentorajapintaan liitytään omalla ohjelmistolla, joka yhtenäistää eri komentorajapinnat heidän sisäiseen standardimuotoonsa. He myös käyttävät mahdollisuuksien mukaan ROS:sia laitekohtaisessa simuloinnissa. 

Vuonna 2017 Fleetonomy.ai otti osaa brittien Defence and Security Accelerator (DASA) kisaan kehittäen Uber-tyylisen toimituspalvelun droneilla, hyödyntäen 3D fotogrammetrian fuusiodataa ja paikallista avointa karttadataa. He saivat kisasta 69,310 £ rahoituksen. (Transparency data Defence and Security Accelerator funded contracts: 1April 2017 to 31 March 2018, 2020)  

Fleetonomy.ai osallistui myös VTT:n autonomisen ajoratkaisun demonstrointiin FortumGO projektissa. Päämäärä 18 km:in matkalla Helsinki-Vantaan lentokentältä Pasilaan oli näyttää mobiiliuden liikkuvuus, yhteydet ja automatisointi. Näin nähdään miten autonomiset sähköiset ajoneuvot vaikuttavat liikenteeseen vähentämällä saasteita ja hiilidioksidipäästöjä. (Kantonen, 2020) 

Fleetonomy.ai otti osaa vuonna 2019 käynnistettyyn Autonomy in the Dynamic World-kilpailuun, jonka tarkoitus oli etsiä innovatiivisia ratkaisuehdotuksia ja tekniikoita autonomisten järjestelmien toiminnan parantamiseksi haastavissa olosuhteissa. Huhtikuussa 2020 DASA julkisti tehneensä 21 sopimusta, joiden yhteisarvo on 2.1 M £. Fleetonomy.ai on yksi voittaneista yrityksistä. (News story DASA awards £2-million to fast track autonomous vehicles in harsh conditions, 2020) 

<!-- (”Monen UAV:n ja UGV:n komentorajapinta laitteen puolesta on toteutettu ROS:lla. Me liitymme laitekohtaiseen komentorajapintaan omalla ohjelmistollamme, joka yhtenäistää eri komentorajapinnat meidän sisäiseen standardimuotoomme. Lisäksi olemme mahdollisuuksien mukaan käyttäneet myös ROS:sia laitekohtaisessa simuloinnissa.” Markus Kantonen, Fleetonomy.ai) Tää ei kuulu mukaan.   -->

<p>&nbsp;</p>  
### IT-palveluita ja ohjelmistoratkaisuja
Solteq?

<p>&nbsp;</p>  
### Tekoäly robotiikka jätteiden lajitteluun
Zenrobotics?

<p>&nbsp;</p>  
### Devecto, Espoo?

<p>&nbsp;</p>  
### Cargotec, Tampere?

<p>&nbsp;</p>  
# Alan tutkimus ja kehitys
Jotain juttua tähän 

<p>&nbsp;</p>  
## Mikrokirurginen robotin tutkimusalusta

The Hamlyn Centre for Robotics Surgery, Imperial College Lontoossa on yksi kuudesta Institute of Global Health Innovation’s (IGHI) tutkimuskeskuksista, jotka tukevat terveydenhuollon innovaatioiden tunnistamista, kehittämistä ja levittämistä. (About us, 2020) Nykyisin saatavilla olevat mikrokirurgisten taitojen kehittämistä ja nopeuttamista tukevat robottiavusteiset mikrokirurgian (RAMS, Robot-Assisted Micro-Surgery) koulutusalustat on pääsääntöisesti suunniteltu makromittakaavassa minimalistisen invasiiviseen leikkaukseen. Siksi Hamlyn Centre on nähnyt tarpeelliseksi kehittää oma mikrokirurgisen robotin tutkimusalusta. He kehittävät mikrokirurgista robotin tutkimusalustaa (MRRP, Microsurgical Robot Research Platform) joka sisältää orjarobotin, jossa on kaksikätinen manipulaattori, kaksi pääkontrolleria sekä näköjärjestelmä (Kuva  ). Se tukee joustavasti monia mikrokirurgisia työkaluja. Ohjelmiston arkkitehtuuri pohjautuu ROS:iin, jota voidaan laajentaa. Eri rajapintoja tutkimalla päädyttiin valitsemaan isäntä-orja-kartoitusstrategia.  

![Kuva18](assets/images/Kirurgirobot.png)
##### Orjarobotin CAD malli MRRP:lle

<p>&nbsp;</p>  
Orjarobotin kinemaattinen ohjaus perustuu SmarPod API:iin (Application Programming Interface) (Kuva   ). Modulaarista ohjausjärjestelmää käytetään ohjaamaan orjarobottimanipulaattorien pietsomoottoreita samalla kun alemman tason muodostavat kaksi harjatonta DC moottorinohjainta käytetään ohjaamaan moottoroituja mikroatuloita. Suuntauksen ohjaamiseksi ohjausjärjestelmällä voi olla 1 kHz näytteenottotaajuus. Järjestelmässä käytetään ROS väliohjelmistoa MRRP yhteyden luomiseksi. He kehittivät ROS-to-SmarPod API-sillan komponenteilla, jotka julkaisevat robotin tilat ROS-sanomina. Reaaliaikainen kinemaattinen ja visuaalinen data voidaan tilata ROS-viesteinä korkeatasoisen apuprosessin saamiseksi. Päämanipulaattorin ohjauskomennot, joita järjestelmä tuottaa ihmisten tai älykkään järjestelmän välityksellä voidaan julkaista ROS topiceina jotta MRRP- robotin päätelaite saadaan asetettua haluttuun asentoon karteesisessa tilassa. Kädessä pidettävällä isäntäohjaimella operatiiviset käskyt generoidaan OpenCV:hen perustuvalla liikkeenseuranta moduulilla. Laskenta ja käsittely on toteutettavissa Python, C++ ja C-ohjelmointikielillä. Käyttöliittymien kehittäminen mahdollistuu QT-pohjaisella GUI:lla (Graphical User Interface). (Zhang;Chen;Li;Salinas;& Yang, 2019) 

![Kuva19](/assets/images/Ohjelmistoarkkitehtuuri.png)
##### Ohjelmistoarkkitehtuuri MRRP:lle

<p>&nbsp;</p>  
## Kappaleen piirteiden havaitseminen

Saksassa sijaitseva Soutwest Research Institute:n (SwRI) ROS Industrial-tiimi kehittää 3D-tunnistinjärjestelmiin hybridia lähestymistapaa, jossa kehittyneet 2D-tunnistimet integroidaan ROS 3D-tunnistuslinjalle kappaleen piirteiden havaitsemiseksi ja jotta tunnistin voidaan päivittää joustavasti ilman muutoksia muuhun järjestelmään. Teollisissa sovelluksissa on usein 3D-havaintodataa 3D-syvyyskameroista, jotka tuottavat myös 2D-video suoratoistoa. ROS-työkaluilla tuota 2D-video suoratoistoa voidaan käyttää haluttujen kappaleiden havaitsemisemiseksi ja projisoida ne takaisin 3D-dataan. Semanttisesti merkityn 3D-verkon aikaansaamiseksi tunnistetut piirteet voidaan yhdistää skannauksen aikana. Verkon päälle voidaan generoida työstöratoja, jotka saadaan havaituista kappaleista. Lähestymistavan arvioimiseksi kehitettiin esimerkki hitsausmenetelmä, jossa jokainen osa oli sarja kiinnehitsattuja alumiinilevyjä, mutta joiden tarkkaa kokoa tai sijaintia ei tiedetty. (Powelson, 2020) (Kuva  ) 

![Kuva20](/assets/images/Hitsauskoe.png)
##### Kokeellinen hitsausmenetelmä

<p>&nbsp;</p>  
Järjestelmä etenee käyttäen ROS-työkaluja. Aluksi kameraohjain toimittaa värillisen pistepilven TSDF-solmulle (Truncated Signed Distance Field), joka rekonstruoi ympäristön geometrian. Samalla pistepilviä huomioiva solmu erottelee pikseliin kohdistetun 2D-kuvan pistepilvestä ja lähettää sen ROS-palvelun kautta satunnaisille 2D-tunnistimille, joka palauttaa naamion, jossa on leima jokaiselle kuvapikselille. Näitä leimoja uudelleen värjätään pistepilven merkitsemiseksi. Tulokset voidaan yhdistää avoimen lähdekoodin octomap_serveriä käyttämällä. Skannauksen lopussa YAK-kirjasto toimittaa 3D-verkon ympäristöstä ja octomap antaa octomapin, joka on väritetty semanttisilla leimoilla. Tesseract-törmäyksen tarkistusrajapintoja voidaan käyttää havainnoimaan kolmioverkkoon liittyvät vokselit, jolloin geometrinen verkko lisätään semanttiseen dataan. (Powelson, 2020) 

![Kuva21](/assets/images/Hitsikuvat.png)
##### Vasemmalla näkyy 2D kuva ja havaittu sauma. Oikealla näkyy 3D-verkko ja yhdistetty 3D havaittu hitsaussauma

<p>&nbsp;</p>  
## Ascento: kaksipyöräinen hyppäävä robotti

Sveitsissä joukko insinööriopiskelijoita ETH Zürichin tutkimus instituutista on kehittänyt tasapainottelevan kaksipyöräisen robotin. Ascenton (Kuva  ) rakennekomponentit luotiin topologisella optimoinnilla (Kuva   ) ja ne on kokonaan 3D-tulostettu polyamidi 12:sta (PA 12) käyttäen selektiivistä lasersintraus (SLS) tekniikkaa. 

![Kuva22](/assets/images/Ascento.png)
##### Ascento

<p>&nbsp;</p>  
Jalkojen optimoitu geometria erottaa ajo- ja hyppyliikkeet antaen näin robotin taipua erilaisissa tippumisskenaarioissa. LQR (Linear Quadratic Regulator) kontrollerilla saavutetaan vakaa ajo. Palautuakseen erilaisista hyppy- tai tippumisliikkeistä robotti käyttää peräkkäismyötäkytkentäistä säätökontrolleria, jossa on takaisinkytkennän seuranta. Ascentossa on keskusyksikkönä Intel NUC i7, IMU (Inertial Measurement Unit) sekä mikrokontrolleri mahdollistamaan yhteydenpito tietokoneen ja IMU:n välillä. Moottorien virrankulutukseen on akku, joka koostuu neljästä sarjaan kytketystä kolmekennoisesta litiuminonipolymeeriakusta (LiPO). Tietokone ja muut elektroniset laitteet saavat virtansa neljäkennoisesta LiPO akusta. Ohjelmiston on oltava laskennallisesti tehokas, jotta suuren kaistanleveyden ohjaimet mahdollistuvat. Kaikki ohjelmistot on kirjoitettu C++:lla. ROS:sia käytetään korkean tason viestintään. Kalman suodatinta toimii IMU:n ja moottorin kooderi mittauksista saaduilla anturitiedoilla. Ascentoa voidaan kauko-ohjata mutta se voi myös operoida täysin autonomisesti käyttäen kameroita ja antureita. Se painaa 10.4 kg ja sen huippunopeus on 8 km/h. Suurin mahdollinen hyppykorkeus on 0.4 m ja operointiaika on n. 1,5 h. (Coxworth, 2020) (Klemm, ym., 2019) 

![Kuva23](/assets/images/Topologiset.png)
##### Topologialla optimoitu osa

<p>&nbsp;</p>  
# Hankkeen onnistuminen

<p>&nbsp;</p>  
# Tulevaisuus

<p>&nbsp;</p>  
# Yhteenveto

<p>&nbsp;</p>  
# Lähteet










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
