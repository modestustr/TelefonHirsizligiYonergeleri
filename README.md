# Android Telefon Hirsizligi Acil Mudahale Konsolu

Android telefonunuz kayboldugunda veya calindiginda izlenecek adimlari tek bir masaustu uygulamasinda toplar. Kontrol listesi, ilgili kurtarma sayfalarina hizli erisim, zaman damgali olay kaydi ve sifreli yerel cihaz kasasi sunar.

> **Onemli:** Uygulama uzaktan kilitleme, konum alma, banka veya operator islemlerini sizin yerinize yapmaz. Ekrandaki adimlari ve resmi hizmet baglantilarini kullanarak islemleri kendiniz gerceklestirin. Sonuclar Google, mobil operator, banka ve cihaz ureticisinin hizmetlerine ve kosullarina baglidir.

## Ozellikler

- Hirsizlik sonrasi acil adimlari zaman araliklarina gore siralayan kontrol listesi.
- Google Cihazimi Bul ve Android Remote Lock gibi resmi sayfalari tarayicida acan kisayollar.
- Olaylari saat dilimi bilgisi iceren ISO-8601 zaman damgalariyla kaydetme; not ve takip numarasi ekleme.
- IMEI, telefon numarasi ve 2FA yedek kodlarini ana parolayla sifrelenen yerel kasada saklama.
- IMEI ve telefon numarasini panoya kopyalama; 2FA yedek kodlarini sirayla kopyalama.
- USB ile bagli ve yetkilendirilmis Android cihazdan ADB araciligiyla desteklenen cihaz bilgilerini alma.
- Resmi tutanak dosyasina yazmadan arayuzu denemek icin tatbikat modu.

## Gereksinimler

- Windows 10/11 ve Python 3.11 veya 3.12.
- Python ile gelen Tkinter bileseni.
- `cryptography` Python paketi.
- (Istege bagli) USB cihaz bilgisi aktarimi icin Android SDK Platform-Tools (ADB).

ADB olmadan da uygulamayi kullanabilir ve cihaz bilgilerini elle girebilirsiniz. Android surumu veya uretici kisitlamalari IMEI ya da telefon numarasinin ADB ile okunmasini engelleyebilir.

## Kurulum ve calistirma

Depoyu indirin veya klonlayin, proje klasorunde asagidaki komutlari calistirin:

```powershell
python -m pip install cryptography
python app.py
```

Windows'ta `run.bat` dosyasina cift tiklayarak da baslatabilirsiniz. Tatbikat modunu baslangicta acmak icin:

```powershell
python app.py --dry-run
```

Ilk acilista kasa icin en az 8 karakterli bir ana parola olusturun. Ardindan **Cihaz Bilgilerini Duzenle** bolumunden kendi bilgilerinizi girip **Sifrele ve Kaydet** secenegini kullanin. Kasayi acmak icin ayni parolayi girmeniz gerekir.

## Veri ve gizlilik

- Sifreli kasa `device_vault.enc` dosyasinda, uygulama dosyasinin yaninda tutulur. Bu dosya parolaniz olmadan acilamaz; parola unutulursa kurtarma yolu yoktur. Parolayi ve kasanin guvenli yedegini ayri yerlerde saklayin.
- IMEI, telefon numarasi ve yedek kodlari gercek olayda kullanmadan once kendi bilgilerinizle degistirin. Uygulama ilk kurulumda ornek/yer tutucu degerler icerir.
- Resmi olay kaydi, Masaustu klasoru varsa oraya; yoksa uygulama klasorune yazilir. Kayit ilk canli islemde olusturulur. Tatbikat modu acikken olaylar yalnizca uygulama penceresinde gosterilir; resmi tutanak dosyasina yazilmaz.
- `device_vault.enc` ve olay kayitlari Git tarafindan yok sayilir. Sifreli olmasi, kasa dosyasinin veya gercek cihaz bilgilerinin herkese acik bir depoda paylasilmasini guvenli hale getirmez.
- ADB kullanirken yalnizca kendi cihazinizda veya erisim izniniz olan cihazlarda USB hata ayiklamayi etkinlestirin. Uygulama Android'in izinlerini veya uretici kisitlamalarini asmaya calismaz.

## Lisans

Lisans bilgisi icin depodaki [LICENSE](LICENSE) dosyasina bakin.
