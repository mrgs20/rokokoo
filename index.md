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




## ROS 1


## ROS 2

### micto-ROS

### ROS + Matlab & Simulink

## ROS health

## ROS Industrial

### Liitännät muihin järjestelmiin

### MoveIt

### Gazebo

### Rviz

### Neuroverkot ja syväoppiminen

# Turvallisuus verkossa


# ROS tuettuja antureita

Erilaiset anturit kuuluvat jo melkein jokaisen arkeen. Antureilla mitataan lämpötilaa, etäisyyttä, ilman kosteutta, tasataan paineita ja havaitaan mahdollinen tulipalon aiheuttama savu tai häkä. Käyttökohteita ja tarkoituksia on lukemattomia. Anturit ovat laitteita, jotka mittaavat fyysistä syötettä ja muuntavat ne tiedoksi, jonka joko ihminen tai kone voi tulkita. ROS:sin avulla robotti kehittää tietoisuutta ympäristöstään käyttämällä esim. stereonäköä, inertiamittausta sekä 3D-laserskannausta. Robotti yhdistää keräämänsä tiedot, jotta se tietää missä se on, minne se on menossa tai mitä mahdollisia esteitä on matkalla. (A Case Study: Developing a ROS Robot with On-Board Computing for a University Robotics Department, 2020) Hyvä listaus ROS antureita löytyy ROS wiki sivistolta: http://wiki.ros.org/Sensors.  

## Velodyne Lidar (Velodyne)

Velodyne on 1983 perustettu yritys, joka tarjoaa tehokkaimpia ja älykkäimpiä markkinoilla olevia etäisyydenmittauslaitteita autonomiaan ja kuljettajan avustukseen. (Velodyne Lidar, Inc., n.d) Lidar (Light Detection and Ranging) kutsutaan usein myös laserskannaukseksi tai 3D-skannaukseksi. Lidar käyttää silmille turvallisia lasersäteitä muodostaakseen 3D-esityksen ympäristöstään. Se laskee etäisyyksiä lähettämällä laservalopulssin ympäristöönsä ja laskee ajan, joka pulssilta, kuluu heijastua kohteesta takaisin. Toistamalla prosessia miljoonia kertoja sekunnissa saadaan tarkka reaaliaikainen 3D kartta. Velodyne voidaan liittää ROS:iin ja generoida pilveen pistetietoja raakadatasta. (What is LIDAR?, 2020)  

![Kuva1](assets/images/Velodyne.png)
##### Velodyne simulointi Gazebolla

![Kuva2](/assets/images/Velodyne_Rviz.png)
##### Velodyne anturi visualisaatio Rviz:lla

## ZED 2 kamera (Stereolabs)

Stereolabs on markkinoiden johtava 3D-syvyys- ja liiketunnistusratkaisujen toimittaja. Heidän tuotteensa perustuu stereonäköön sekä tekoälyyn. ZED 2 on ensimmäinen stereo kamera, joka käyttää neuroverkkoa tuottaakseen ihmismäisen näkymän. Siinä on sisäänrakennettu IMU, barometri sekä magnetometri, joilla se kerää reaaliaikaista synkronoitua inertia-, korkeus- ja magneettikenttädataa. Alkuperäisillä 16:9 antureilla ja 8-elementteisillä äärimmäisen terävillä linsseillä, joissa vääristymä on optisesti korjattu ja joissa on laajempi f/1,8 aukko, voi tallentaa videon ja syvyyden jopa 120° näkökenttään 40 % suuremmalla valomäärällä. (Built for the Spatial AI era, 2020) 

![Kuva3](/assets/images/ZED_2.png)
##### ZED 2 visualisaatio Rviz:llä

## TeraRanger (Terabee)

Terabee perustettiin vuonna 2012 tarjoamaan innovatiivista dronepalvelua erityisen vaativiin tarkastuksiin. Vuonna 2013 näki European Centre of Nuclear Research (CERN) mahdollisen potentiaalin ja tiedusteli, kykenisivätkö he kehittämään täysin autonomimisen dronen tutkimaan Large Hardon Colloder (LHC) tunnelia, joka on maailman suurin ja tehokkain hiukkaskiihdytin. Markkinoilla huomattiin olevan aukko ja nykyisin Terabee kehittää ja valmistaa monia erilaisia anturimoduleja kuten 2D-infrapuna LED Time-of-Flight (ToF) etäisyysantureita, 3D ToF syvyys- ja lämpökameroita. (About us, n.d) (The Large Hadron Collider, 2020) Esimerkkinä mainittakoon TeraRanger Evo 60 m (Kuva  ), joka kuuluu TeraRanger tuoteperheeseen. Se on pieni ja kevyt, pitkän kantaman ToF- anturi, joka tarjoaa kalibroidut etäisyyslukemat millimetreinä ja käyttää LED teknologiaa laserin sijaan. (teraranger, 2019)  

![Kuva4](/assets/images/TeraRanger.png)
##### TeraRanger Evo 60 m 

## Xsense MTi IMU (Xsens)

Xsens on vuonna 2000 perustettu innovaatiojohtaja 3D-liikkeenseuranta- ja tallennusteknologiassa. Kuten nimikin sanoo perustuvat inertia-anturit inertiaan eli hitausmomenttiin. Ne vaihtelevat MEMS-inertia-antureiden muutaman neliömillin kokoisista erittäin tarkkoihin rengaslasergyroskooppeihin, joiden halkaisija saattaa olla jopa 50 cm kokoinen (Kuva  ). Inertial Measurement Unit (IMU) on muista riippumaton järjestelmä, joka mittaa lineaarista ja angulaarista liikettä kolmen gyroskoopin ja kiihtyvyysmittarin avulla. (About us, n.d) (Inertial Sensor Modules, n.d) 

![Kuva5](/assets/images/Xsens.png)
##### Xsens MTi

## Hokuyo Laser (Hokuyo)

Intel® RealSense™ D400-sarjan syvyyskamerat käyttävät stereonäkymää laskeakseen syvyyden. Stereokuva toteutetaan käyttämällä vasenta ja oikeaa kuvanninta sekä valinnaista infrapunaprojektoria. Matala tekstuurisissa näkymissä infrapunaprojektori heijastaa näkymätöntä staattista IR (Infrared) kuvioita parantaakseen syvyystarkkuutta. Kuvantimet tallentavat näkymän ja lähettävät datan syvyysnäköprosessorille, joka laskee kuvan jokaiselle pikselille syvyysarvot korreloimalla pisteitä keskenään ja siirtämällä pisteitä kuvien välillä. Syvyyspikseliarvot prosessoidaan syvyyskehyksen luomiseksi. Perättäisistä syvyyskehyksistä saadaan luotua syvyysvideostriimaus (Kuva  ). (Intel® RealSenseTM Product Family D400 Series, 2020) 

![Kuva6](/assets/images/Intel_Realsense.png)
##### Aktiivinen IR Stereonäkö teknologia

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

# ROS:sin hyödyntäminen

Älykkäiden robottien suunnittelu ja rakentaminen ei ole niin yksinkertaista ja suoraviivaista kuin se voisi olla. Monet robotiikassa työskentelevät joutuivat usein aloittamaan aivan alusta aloittaessaan uuden projektin ja uudelleen kehittää ohjelmistoinfrastruktuurin joihin robottien algoritmit perustuvat. Jaetut työkalut ja resurssit olivat vähissä. ROS:sin etu on siinä, että suurimmassa osassa tapauksia ohjelmiston on jo todettu toimivan käytännössä. (Mok, 2020)

## Case-esimerkkejä maailmalta

Tähän kans sit jotain sopivaa tekstiä

### Teollisuusrobotit

ISO 8373:2012 mukaan teollisuusrobotti on autonomisesti ohjautuva, uudelleen ohjelmoitavissa oleva, moneen tarkoitukseen sopiva kolme tai useampi akselinen manipulaattori, joka voidaan asentaa joko kiinteästi tai käyttää mobiilina teollisuuden automaatiosovelluksissa. Näitä ovat mm. lineaari-, SCARA-, delta-, ja nivelrobotit. (Mueller, 2019) Koneoppiminen, AI (Artificial Intelligence), IIoT (Industrial Internet of Things) sekä ihmisen ja koneen yhteistyö sekä autonomiset mobiilijärjestelmät ovat tätä päivää. Edessä on kuitenkin suuria haasteita, kuten nopeasti muuttuvat kuluttajasuuntaukset, resurssien puute, ammattitaitoisten työtekijöiden puute, ikääntyvä yhteiskunta ja paikallisten tuotteiden kysyntä. Joustava teollisuusrobotiikka mahdollistaa ratkaisun näihin haasteisiin. (World Robotics 2020, 2020) 

### MotoPlus ™ SDK ohjain 

Japanilainen Yaskawa Motoman oli yksi ensimmäisistä yhteistyö-, ja teollisuusrobottien valmistajista, joka hyödyntää ROS:sia. Yaskawa:lla on ROS-I ajuri YRC1000, YRC1000micro, DX200 ja DX100 robottien ohjaimiin. Ohjain kehitettiin käyttämällä MotoPlus™ SDK:ta (Kuva  ). Se sisältää C/C++ yhteensopivan ohjelmointirajapinnan (API, Application Programming Interface) jolla ohjelmoijat voivat tehdä reaaliaikaisia sovelluksia, jotka toimivat robotin alkuperäisessä VxWorks-käyttöjärjestelmässä. Rajoitettujen sovellusten kehittäminen voimanhallintaan, visuaaliseen robotin ohjaukseen sekä geneeriseen anturien integrointiin mahdollistuu. (Specific Unified Robot Description Formats (URDF) on saatavana robottien käsivarsien simulointiin. (Vozel, 2019) 

![Kuva7](/assets/images/Liikepaketin_kerrostumat.png)
##### Ros-Industrial liikepaketin kerrostumat sekä miten MotoROS ja Yaskawa Motoman ohjain liittyvät toisiinsa

### Plug’n’play ROS-ohjain 

Tanskalainen Universal Robots on hallitseva kevyiden käsivarsirobottien toimittaja sekä teollisuuteen että tutkimukseen ja opetukseen. Tutkimuskenttä on kehittänyt kolmansien osapuolien ohjaimia, joilla ROS yhteisö on voinut kommunikoida UR robottien kanssa. ROS yhteisöstä löytyy yli 200 haaraa, jotka ovat UR yhteensopivia. UR ei silti koskaan ole ollut kehittämässä tai tukemassa näitä ohjaimia. Saatavilla on monia yhteisön kehittämiä ohjaimia, joista ei tiedä millä niistä on viimeisimmät ominaisuudet tai mitkä niistä tukevat oikeaa UR ohjelmaversiota. (Madsen, 2019) 

Jotta Universal Robots: in parhaita ominaisuuksia hyödynnettäisiin, kehittivät he yhteistyössä saksalaisen tutkimuslaitoksen, FZI (Forschungszentrum Informatik, Research Center for Information Technology) kanssa Universal Robots: in tukeman ROS-ohjaimen, jotta siitä saatiin vakaa ja kestävä. Ohjain julkaistiin markkinoille lokakuussa 2019. Tämä on ”plug’n’play”-tyylinen, helppokäyttöinen ohjain UR roboteille. Se hyödyntää robotin pääominaisuuksia, jotta se kykenee parhaaseen suorituskykykyynsä ja tarjoaa parhaimman teollisuusluokan rajapinnan, jonka nykyinen ROS käytäntö mahdollistaa. Ohjain sisältää spesifit robotin kalibrointidatat parhaaseen tarkkuuteen. Ohjain tulee olemaan avoin lähdekoodi ja nojaa tulevaisuuden yhteisökehitykseen. Ohjain on tarkoitettu CB3 ja e-sarjalaisille, joissa RTDE (Real-Time Data Exhange) on saatavilla (Kuva  ). (Madsen, 2019; Universal Robots ROS driver, 2020) 

![Kuva8](/assets/images/Universal.png)
##### Universal robots:in e-sarjalaiset



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
