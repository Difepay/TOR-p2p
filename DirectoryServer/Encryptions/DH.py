# Libraries
from random import getrandbits, choice


# Classes
class dh:
    """
    An implementation of the DH protocol.
    This class provides methods for generating session key

    Fields:
        * p (int): Prime modulus
        * g (int): Generator (primitive root module p)
    """

    # DH preset parameters
    __PARAMETERS: dict[int, list[dict[str, int]]] = {
        2048: [
            {
                'p':
                    0x00e7f8e7c78754b74f8c14c8322e7e17339953b5e301c9884f1c1c0c1f490e07dd297965b971123e693cf2b70b5615459d88df40db738347b78b2a6b60ed22a2a466d717fc4d584e7f9aef93b4d7cb854d18208ecd07984a199da281d9b85ac92b7f4cd3befc93700fa47c889ed15aeacb5b1ea93fd3752b9f0035398b0c92004cbe271c4039df6ee9708ebd36227ba1e2bf1f0508e1abec9d38e2ae7c900662ad2c26af61f324f5f0a7a94096deb2ab02918611f273a1b5a7ef91fadb3d45477d2f6b88550b100d64d425ce81b79ef4d4bc8ffa2d470b80219c5b5f80838a76ddf43216c4c78990ffe240f91763e5372a2fef1a5611ecd02665e40994083c0183,
                'g': 2
            },

            {
                'p':
                    0x00dfa6779f66d9da0f70adba0db922a9fadadbb4250253ce3a357c58d45118492c13c1cef3e9e681c62d3931e5035c8bec2f0138885f5addf00d78a803e35537455cb3893feb4e835f4b05306fe5567752d05eeff11a38a8e0480caf7f532859eaa8652f416ea1d8bbe17b1eb6a172db93965affda23ac017af63a4b6f5642c9a98ec811eea6e162125c1e9f463d50df893757e17a5d2e04792ff20691f389fd8d69ab3bc0da63c857660168be9710007beffdfc7af025a2f877be602a3480d6c0cf55fd201398b6c17a9bed2e6ba6faacb98aca305bfcf3a1cbd9d5b82651c014c6d52a9d604279724adba87790cbd49fed19e1df8388ab132db26d9e5574868b,
                'g': 2
            },
            {
                'p':
                    0x00cc97f35babd90de45b943d358792629dfe081a636e5eab4eceb8d5a7b32938e6a1c233336dc89da6063c2698ce9d5310fd9c93ac72675713f4803f3add1f7a3eaeb3e980f389246be67f60227823fe3c794176ac231d2253fd4a7b016b47f7a61fcc78b077ef2fb78b2fc56230eb25c2a5b68eefb655a170af7495230a6c20fbdb6f4990b30e98a5e2f1d2ed735e6c7ad875adb94be0c373a560948068ef9310385f2eb325eb468f1accc27febc38dd06ac975dde3243c6d62d6e8a4a9562ce889d2da0938246c0df8218a528668d217f7367e2e5adb6959783b0b77eb6db4ee14282c68d99773da3a35c71a381043e13e46e520230ff48cb51d960615ff4b73,
                'g': 2
            },
            {
                'p':
                    0x00fa7eb1e35adc479c8095da50df6cb9a714060abbeeaa213fed48c0f1360624ca674a2968ed48815451586a558af5c5f09b0816cd129889b6c08b79f55906f86e8c9c2fd55e90374ea11a797d7f91d0548441c405031c6fde4587413be9758f26269ce578c562ebd4c02599470bdb7b2a01c358551d0a63f121b244969fed7d0c0e8a963e6046571f2a2773f8468125d1fa8e3c3365abdb6ac51094f38e8510f0b445d7f38f459e718a364f6463ab8bc733d74b3926e1e6b8e96147063eb74817031c5bd6564fb2086cfc93ac9c7ed44611eeedf90ff4394c1691cd7df0d384eb8ad37bc3e82da8bf9410fbdcdf594a24a6e1374f082fa73e75a2e36b6e3fac7b,
                'g': 2
            },
            {
                'p':
                    0x008848480622c91e14cf34afebf9a93d540e98ffa3a65229480f02b859b20f91654f6efdd718fc1c818cca7cc1f48e830ce191208ded3778fe13bbfcb1d8a4f7572df7e6a4b1419c57c0bb2d8dd01d931a101fcf16511e45ed9dcf0304741547995c6b319a38cd7e6dd8081d2f0c598aef3290aa70852bb0a93a1c2b6cbf2045d0ed48965784b1bc6795433f54197cfa8b5255c5b05382e38e01affa5a0344c0bc89774a3f5ca237bdaa43e3e1674cbca5bdc61846925d49a0473ac4df24156558780fd6f1beb826ab9374f40499047ff89ca891be966c461004015cb6715f95cd62364ef405ee772d5748ad2e5c14b70d3699d276a04843978db10f2faab78f23,
                'g': 2
            },
            {
                'p':
                    0x00fbddb53dd6a5ed99e7694af224f8e189841cb94047a64a1fe00fdeeb8385c913c9b551e5291f141e3300d4f219c1dedf67e52e1550bc7395f430eb17e7d9d1ea031e96349660bed51e94cbe02a567955aeb40d95f78eb2d62bf3f7916b59df8b7e483a6d6500af4bfec11cbad26ed5c404267f2c09c4aac1b474431d8853c598cc80c9573e1205e3fafed9aa5f1f185568112c805f85c01b2ba770c229c3c7e95db1f22384cb4feab2b4b19c6156e936f68b8312555283722a2486c04e2acfa05eae49890a4467df00722a98903899087148919bd0939069e44b093f5f6ff2e5ad5e2f3e506d08de08af2bafdc6c27d78dbf6efd174f9c7e338482c4f38352d7,
                'g': 5
            },
            {
                'p':
                    0x00ff96b6753d7d31dd590f530ada9d50a6be8aaa91e7c70b1a04bbd50fc49fc39eb964ad0dec559439dd01bbe8132862b104c451418f8d143b5d35b2ea69a5fb1e42ff55f80d13337c36e843df216e30625c57409a6ca1e993651b85172a94cebfc6824ea9a264f549b05d9a1172a63e115ef0ff947f408701eae12e823aa686c67cb0dd50504b61fc70a41375929f5b98dfdca41fb4b36d5724a52787f247fd3a4fb5f0725c6776279b741466562a00a56965670c571a5cf13f9818b7422f8059281a1c1739d435e52e0d4e99d9d585db8c1af1eea9520db985f0fe4441a119e99513824438edb8455379ff1e0270eb2278952701cef8425e13a43f83eed0dceb,
                'g': 5
            },
            {
                'p':
                    0x00ac4b88766a75e09e729602dba0f4b30086bc256bfbed4d1147e376fec208055baff4730dee910f4001febd02e2da03e606e472f2bf21997bab283dd08f5da43c023b979744bf9bad7e01cd6649c74508e5e4db4fe1757cac67423c660bfd637934a0b6810d12e19892ef4dcdce4ccabf47fdca665798b89dc65cb32d983e9465aae66372d0513e34f9c7f8a2eab2d843743e5f2371e049fcd81ca8ade2493294fb168fb8487d0a597527d2312ea424974be0d192b0dc69e9b2ee31361480c5bb4f08beaedfd00373b487723de9956f50eb2c647e7c792e3e8016a4a97942b8c409f3695f12949848806863015aff49103abaa754ace77b850f49f720c51adfb7,
                'g': 5
            },
            {
                'p':
                    0x00ecea86a43e08a2d3770d37a1785753ea236207629aae71f39a2417ecd3296616471b4e3b053daf232cbadb28f4c3c10d67899d068eea2e58fa4b75d122ad2764cc45415013ff574fe6436a6e370349292a9b0290f106b250f68ba7c426eeff978b7d56a0858dc10897a64d781550b55f708eb2102811b39d4e393772005e2cf7223f673311130d823fcf6655406c7750082b2a89e91293c39123a03283458e0b7dea675c9635e22f4b366ffbe14ebe0f3774e605e054668ab9a23e7e1be52a4a2d72ebe1182d8db3fa233a004ac0c6cdf3bfa13898b6860f6ff90241d804b8043ef7542931b1a665dc58b2a69976841716ef719ce3a4cefcd42434ce7efddc9f,
                'g': 5
            },
            {
                'p':
                    0x00f4152f2df4b71705d28e7c79c4c098ae959d0cb770f563a5783584543bebf763bb6c756c0c46b3370e54ac4cf0d85073a24474c018ffbac6cb72526e512a0959a6cefd2b6780ee3b11ccd485f4beece381bc9901ed1904c36f1fe9961069c7e303e2992f12820b7e5e2239e6410ddf09be2a36a0c10cfa20ffea47db9175798d71398d7295f365ae56cf43a0dc62f06dd568261afcf2f0d29aecf28a44ddf00c3fd6a14be5da8aa6b5b3cbe6fde1f64aaceaf6b90006ed6448e25b50ceb4fb14ede419c656b3f1d00e92ad6b1e261853fde2bfd03f1fc3f478411782ec216144cf64ff85d2b534fd0e49a916fa4e497b209a4ca1b5db772e2415205c4287ddcf,
                'g': 5
            },
        ]
    }

    @staticmethod
    def generate_parameters(key_size: int = 2048) -> tuple[int, int]:
        """
        Generates Diffie-Hellman parameters (p, g) for a given key size
        :param key_size: The desired key size (default = 2048 bits)
        :return: A tuple containing the prime modulus (p) and generator (g)
        """
        if key_size not in dh.__PARAMETERS:
            raise ValueError(f"Key size {key_size} is not supported")

        params_list = dh.__PARAMETERS[key_size]
        selected_params = choice(params_list)
        return selected_params['p'], selected_params['g']

    def __init__(self, parameters: tuple[int, int] = ()):
        """
        Initializes a Diffie-Hellman instance with the given parameters
        :param parameters: A tuple containing the prime modulus (p) and generator (g)
        """
        if not parameters:
            parameters = dh.generate_parameters()

        self.__p, self.__g = parameters

    def generate_public_key(self, private_number: int) -> int:
        """
        Generates a public key based on a private number
        :param private_number: The private number
        :return: `public key = g^private_number (mod p)`
        """
        return pow(self.__g, private_number, self.__p)

    def exchange(self, public_key_other: int, private_number: int) -> int:
        """
        Computes the shared secret key by exchanging public keys with others
        :param public_key_other: The other side's public key
        :param private_number: The private number of the current side
        :return: `secret_session_key = public_key_other^private_number (mod p)`
        """
        return pow(public_key_other, private_number, self.__p)

    @staticmethod
    def generate_private_number(number_bit_length: int = 2048) -> int:
        """
        *Static method*. Generates a random number
        :param number_bit_length: The desired private number (default = 2048 bits)
        :return: A generated private number
        """
        return getrandbits(number_bit_length)
