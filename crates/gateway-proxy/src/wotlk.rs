pub mod opcode {
    pub struct Opcode;

    impl Opcode {
        // Movement opcodes (u16) used by the proxy injector.
        pub const MSG_MOVE_START_FORWARD: u16 = 181;
        pub const MSG_MOVE_START_BACKWARD: u16 = 182;
        pub const MSG_MOVE_STOP: u16 = 183;
        pub const MSG_MOVE_START_STRAFE_LEFT: u16 = 184;
        pub const MSG_MOVE_START_STRAFE_RIGHT: u16 = 185;
        pub const MSG_MOVE_STOP_STRAFE: u16 = 186;
        pub const MSG_MOVE_JUMP: u16 = 187;
        pub const MSG_MOVE_START_TURN_LEFT: u16 = 188;
        pub const MSG_MOVE_START_TURN_RIGHT: u16 = 189;
        pub const MSG_MOVE_STOP_TURN: u16 = 190;
        pub const MSG_MOVE_START_PITCH_UP: u16 = 191;
        pub const MSG_MOVE_START_PITCH_DOWN: u16 = 192;
        pub const MSG_MOVE_STOP_PITCH: u16 = 193;
        pub const MSG_MOVE_FALL_LAND: u16 = 201;
        pub const MSG_MOVE_START_SWIM: u16 = 202;
        pub const MSG_MOVE_STOP_SWIM: u16 = 203;
        pub const MSG_MOVE_SET_FACING: u16 = 218;
        pub const MSG_MOVE_SET_PITCH: u16 = 219;
        pub const MSG_MOVE_HEARTBEAT: u16 = 238;

        // Chat/emote.
        pub const CMSG_TEXT_EMOTE: u32 = 260;

        // Character login (client selects a character and enters the world).
        // AzerothCore/TrinityCore WotLK opcode map: CMSG_PLAYER_LOGIN = 0x03D.
        pub const CMSG_PLAYER_LOGIN: u16 = 0x03D;

        // Targeting / interaction / combat basics.
        // Values are for WoW 3.3.5a / TrinityCore-style opcode maps.
        pub const CMSG_SET_SELECTION: u32 = 0x013D;
        pub const CMSG_ATTACKSWING: u32 = 0x0141;
        pub const CMSG_GOSSIP_HELLO: u32 = 0x017B;

        // Loot.
        // AzerothCore WotLK opcode map:
        // - CMSG_AUTOSTORE_LOOT_ITEM = 0x108
        // - CMSG_LOOT = 0x15D
        // - CMSG_LOOT_MONEY = 0x15E
        // - CMSG_LOOT_RELEASE = 0x15F
        pub const CMSG_AUTOSTORE_LOOT_ITEM: u32 = 0x0108;
        pub const CMSG_LOOT: u32 = 0x015D;
        pub const CMSG_LOOT_MONEY: u32 = 0x015E;
        pub const CMSG_LOOT_RELEASE: u32 = 0x015F;
    }
}

pub mod srp {
    use num_bigint::{BigInt, Sign, ToBigInt};
    use sha1::{Digest, Sha1};

    #[derive(Debug, Default)]
    pub struct Srp {
        pub session_key: Vec<u8>,
        modulus: BigInt,
        generator: BigInt,
        private_ephemeral: BigInt,
        public_ephemeral: BigInt,
        server_ephemeral: BigInt,
        salt: [u8; 32],
        client_proof: Option<[u8; 20]>,
    }

    impl Srp {
        pub fn init(&mut self, n: &[u8], g: &[u8], server_ephemeral: &[u8; 32], salt: [u8; 32]) {
            self.modulus = BigInt::from_bytes_le(Sign::Plus, n);
            self.generator = BigInt::from_bytes_le(Sign::Plus, g);

            self.private_ephemeral = {
                let private_ephemeral: [u8; 19] = rand::random();
                BigInt::from_bytes_le(Sign::Plus, &private_ephemeral)
            };

            self.public_ephemeral = self
                .generator
                .modpow(&self.private_ephemeral, &self.modulus);
            self.server_ephemeral = BigInt::from_bytes_le(Sign::Plus, server_ephemeral);
            self.salt = salt;
        }

        pub fn public_ephemeral(&mut self) -> [u8; 32] {
            Self::pad_to_32_bytes(self.public_ephemeral.to_bytes_le().1)
        }

        pub fn calculate_proof(&mut self, account: &str) -> [u8; 20] {
            let result = Sha1::new()
                .chain(self.calculate_xor_hash())
                .chain(Self::calculate_account_hash(account))
                .chain(self.salt)
                .chain(self.public_ephemeral.to_bytes_le().1)
                .chain(self.server_ephemeral.to_bytes_le().1)
                .chain(&self.session_key)
                .finalize()
                .to_vec();

            let mut output = [0u8; 20];
            output.copy_from_slice(&result);

            self.client_proof = Some(output);
            output
        }

        pub fn calculate_session_key(&mut self, account: &str, password: &str) {
            let salt = self.salt;
            let x = self.calculate_x(account, password, &salt);
            let verifier = self.generator.modpow(&x, &self.modulus);

            let mut session_key = Self::calculate_interleaved(self.calculate_s(x, verifier));

            while let Some(&0) = session_key.last() {
                session_key.truncate(session_key.len() - 1);
            }

            self.session_key = session_key;
        }

        pub fn validate_proof(&mut self, server_proof: [u8; 20]) -> bool {
            let Some(client_proof) = self.client_proof else {
                // Invalid state: proof was never calculated.
                // Avoid panicking in production; just treat as a failed validation.
                return false;
            };

            let client_proof = {
                let hasher = Sha1::new();
                let result = hasher
                    .chain(self.public_ephemeral())
                    .chain(client_proof)
                    .chain(self.session_key.clone())
                    .finalize();

                let mut hashed_proof = [0u8; 20];
                hashed_proof.copy_from_slice(&result);
                hashed_proof
            };

            client_proof == server_proof
        }

        fn calculate_account_hash(account: &str) -> Vec<u8> {
            Sha1::new().chain(account.as_bytes()).finalize().to_vec()
        }

        fn calculate_xor_hash(&mut self) -> Vec<u8> {
            let n_hash = Sha1::new().chain(self.modulus.to_bytes_le().1).finalize();
            let g_hash = Sha1::new().chain(self.generator.to_bytes_le().1).finalize();

            let mut xor_hash = Vec::new();
            for (index, value) in g_hash.iter().enumerate() {
                xor_hash.push(value ^ n_hash[index]);
            }

            xor_hash
        }

        fn calculate_x(&mut self, account: &str, password: &str, salt: &[u8]) -> BigInt {
            let identity_hash = Sha1::new()
                .chain(format!("{}:{}", account, password).as_bytes())
                .finalize()
                .to_vec();

            let x = Sha1::new()
                .chain(salt)
                .chain(identity_hash)
                .finalize()
                .to_vec();

            BigInt::from_bytes_le(Sign::Plus, &x)
        }

        fn calculate_u(&mut self) -> BigInt {
            let u = Sha1::new()
                .chain(self.public_ephemeral.to_bytes_le().1)
                .chain(self.server_ephemeral.to_bytes_le().1)
                .finalize()
                .to_vec();

            BigInt::from_bytes_le(Sign::Plus, &u)
        }

        fn calculate_s(&mut self, x: BigInt, verifier: BigInt) -> BigInt {
            const K: u8 = 3;
            let u = self.calculate_u();
            let mut s = &self.server_ephemeral - K.to_bigint().unwrap() * verifier;
            s = s.modpow(&(&self.private_ephemeral + u * x), &self.modulus);
            s
        }

        fn calculate_interleaved(s: BigInt) -> Vec<u8> {
            let (even, odd): (Vec<_>, Vec<_>) = Self::pad_to_32_bytes(s.to_bytes_le().1)
                .into_iter()
                .enumerate()
                .partition(|(i, _)| i % 2 == 0);

            let part1 = even.iter().map(|(_, v)| *v).collect::<Vec<u8>>();
            let part2 = odd.iter().map(|(_, v)| *v).collect::<Vec<u8>>();

            let hashed1 = Sha1::new().chain(part1).finalize();
            let hashed2 = Sha1::new().chain(part2).finalize();

            let mut session_key = Vec::new();
            for (index, _) in hashed1.iter().enumerate() {
                session_key.push(hashed1[index]);
                session_key.push(hashed2[index]);
            }

            session_key
        }

        fn pad_to_32_bytes(bytes: Vec<u8>) -> [u8; 32] {
            let mut buffer = [0u8; 32];
            // `BigInt::to_bytes_le()` can, in theory, exceed 32 bytes if the inputs are wrong.
            // Keep behavior non-panicking; in debug builds, surface the invariant.
            debug_assert!(
                bytes.len() <= 32,
                "expected <=32 bytes, got {}",
                bytes.len()
            );
            let n = bytes.len().min(32);
            buffer[..n].copy_from_slice(&bytes[..n]);
            buffer
        }
    }
}

pub mod rc4 {
    use std::fmt::{Debug, Formatter};

    use hmacsha::HmacSha;
    use sha1::Sha1;

    const ENCRYPTION_KEY: [u8; 16] = [
        0xC2, 0xB3, 0x72, 0x3C, 0xC6, 0xAE, 0xD9, 0xB5, 0x34, 0x3C, 0x53, 0xEE, 0x2F, 0x43, 0x67,
        0xCE,
    ];

    const DECRYPTION_KEY: [u8; 16] = [
        0xCC, 0x98, 0xAE, 0x04, 0xE8, 0x97, 0xEA, 0xCA, 0x12, 0xDD, 0xC0, 0x93, 0x42, 0x91, 0x53,
        0x57,
    ];

    pub struct Encryptor {
        instance: RC4,
    }

    impl Encryptor {
        pub fn new(secret: &[u8]) -> Self {
            let mut sync = vec![0u8; 1024];

            let mut encryptor = RC4::new(
                HmacSha::new(&ENCRYPTION_KEY, secret, Sha1::default())
                    .compute_digest()
                    .to_vec(),
            );

            encryptor.encrypt(&mut sync);

            Self {
                instance: encryptor,
            }
        }

        pub fn encrypt(&mut self, data: &mut [u8]) {
            self.instance.encrypt(data);
        }
    }

    impl Debug for Encryptor {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "Encryptor")
        }
    }

    pub struct Decryptor {
        instance: RC4,
    }

    impl Decryptor {
        pub fn new(secret: &[u8]) -> Self {
            let mut sync = vec![0u8; 1024];

            let mut decryptor = RC4::new(
                HmacSha::new(&DECRYPTION_KEY, secret, Sha1::default())
                    .compute_digest()
                    .to_vec(),
            );

            decryptor.encrypt(&mut sync);

            Self {
                instance: decryptor,
            }
        }

        pub fn decrypt(&mut self, data: &mut [u8]) {
            self.instance.encrypt(data);
        }
    }

    impl Debug for Decryptor {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "Decryptor")
        }
    }

    #[derive(Debug)]
    pub struct RC4 {
        i: u8,
        j: u8,
        pub state: [u8; 256],
    }

    impl RC4 {
        pub fn new(key: Vec<u8>) -> Self {
            assert!(!key.is_empty() && key.len() <= 256);

            let mut state = [0u8; 256];
            let mut j: u8 = 0;

            for (i, x) in state.iter_mut().enumerate() {
                *x = i as u8;
            }
            for i in 0..256 {
                j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
                state.swap(i, j as usize);
            }

            Self { i: 0, j: 0, state }
        }

        pub fn next(&mut self) -> u8 {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[self.i as usize]);
            self.state.swap(self.i as usize, self.j as usize);
            self.state
                [(self.state[self.i as usize].wrapping_add(self.state[self.j as usize])) as usize]
        }

        pub fn encrypt(&mut self, data: &mut [u8]) {
            for x in data.iter_mut() {
                *x ^= self.next();
            }
        }
    }
}

pub mod movement {
    use std::io::{Read, Seek, Write};

    use binrw::{BinRead, BinResult, BinWrite, Endian};
    use bitflags::bitflags;

    #[derive(Default, PartialEq, Clone, Copy, Eq, Hash, Debug)]
    pub struct PackedGuid(pub u64);

    impl BinRead for PackedGuid {
        type Args<'a> = ();

        fn read_options<R: Read + Seek>(
            reader: &mut R,
            endian: Endian,
            args: Self::Args<'_>,
        ) -> BinResult<Self> {
            let mask = <u8>::read_options(reader, endian, args)?;
            if mask == 0 {
                return Ok(Self(0));
            }

            let mut guid: u64 = 0;
            for i in 0..8 {
                if (mask & (1 << i)) != 0 {
                    guid |= (<u8>::read_options(reader, endian, args)? as u64) << (i * 8);
                }
            }

            Ok(Self(guid))
        }
    }

    impl BinWrite for PackedGuid {
        type Args<'a> = ();

        fn write_options<W: Write + Seek>(
            &self,
            writer: &mut W,
            _: Endian,
            _: Self::Args<'_>,
        ) -> BinResult<()> {
            let mut guid = self.0;
            let mut packed_guid = [0u8; 9];
            let mut size = 1;
            let mut index = 0;

            while guid != 0 {
                if guid & 0xFF > 0 {
                    packed_guid[0] |= 1 << index;
                    packed_guid[size] = guid as u8;
                    size += 1;
                }
                index += 1;
                guid >>= 8;
            }

            writer.write_all(&packed_guid[..size])?;
            Ok(())
        }
    }

    #[derive(BinRead, BinWrite, PartialEq, Copy, Clone, Default, Debug)]
    #[br(little)]
    #[bw(little)]
    pub struct Point3D {
        pub x: f32,
        pub y: f32,
        pub z: f32,
    }

    #[derive(BinRead, BinWrite, PartialEq, Debug, Clone, Copy)]
    #[br(little)]
    #[bw(little)]
    pub struct OrientedPoint3D {
        pub point: Point3D,
        pub direction: f32,
    }

    bitflags! {
        #[derive(Copy, Clone, Debug, PartialEq)]
        pub struct MovementFlags: u32 {
            const NONE = 0x00000000;
            const FORWARD = 0x00000001;
            const BACKWARD = 0x00000002;
            const STRAFE_LEFT = 0x00000004;
            const STRAFE_RIGHT = 0x00000008;
            const LEFT = 0x00000010;
            const RIGHT = 0x00000020;
            const PITCH_UP = 0x00000040;
            const PITCH_DOWN = 0x00000080;
            const WALKING = 0x00000100;
            // In WotLK movement, this bit indicates the player is on a transport.
            // Keeping the legacy name as an alias since earlier iterations called this "TAXI".
            const ONTRANSPORT = 0x00000200;
            const TAXI = 0x00000200;
            const DISABLE_GRAVITY = 0x00000400;
            const ROOT = 0x00000800;
            const JUMPING = 0x00001000;
            const FALLING_FAR = 0x00002000;
            const PENDING_STOP = 0x00004000;
            const PENDING_STRAFE_STOP = 0x00008000;
            const PENDING_FORWARD = 0x00010000;
            const PENDING_BACKWARD = 0x00020000;
            const PENDING_STRAFE_LEFT = 0x00040000;
            const PENDING_STRAFE_RIGHT = 0x00080000;
            const PENDING_ROOT = 0x00100000;
            const SWIMMING = 0x00200000;
            const ASCENDING = 0x00400000;
            const DESCENDING = 0x00800000;
            const CAN_FLY = 0x01000000;
            const FLYING = 0x02000000;
            const SPLINE_ELEVATION = 0x04000000;
            const SPLINE_ENABLED = 0x08000000;
            const WATERWALKING = 0x10000000;
            const FALLING_SLOW = 0x20000000;
            const HOVER = 0x40000000;
        }
    }

    impl Default for MovementFlags {
        fn default() -> Self {
            Self::NONE
        }
    }

    impl BinRead for MovementFlags {
        type Args<'a> = ();
        fn read_options<R: Read + Seek>(
            reader: &mut R,
            endian: Endian,
            _: Self::Args<'_>,
        ) -> BinResult<Self> {
            let bits = u32::read_options(reader, endian, ())?;
            Ok(MovementFlags::from_bits_truncate(bits))
        }
    }

    impl BinWrite for MovementFlags {
        type Args<'a> = ();
        fn write_options<W: Write + Seek>(
            &self,
            writer: &mut W,
            endian: Endian,
            _: Self::Args<'_>,
        ) -> BinResult<()> {
            u32::write_options(&self.bits(), writer, endian, ())
        }
    }

    bitflags! {
        #[derive(Copy, Clone, Debug, PartialEq)]
        pub struct MovementExtraFlags: u16 {
            const NONE = 0x00000000;
            const NO_STRAFE = 0x00000001;
            const NO_JUMPING = 0x00000002;
            const UNK3 = 0x00000004;
            const FULL_SPEED_TURNING = 0x00000008;
            const FULL_SPEED_PITCHING = 0x00000010;
            const ALWAYS_ALLOW_PITCHING = 0x00000020;
            const UNK7 = 0x00000040;
            const UNK8 = 0x00000080;
            const UNK9 = 0x00000100;
            const UNK10 = 0x00000200;
            const INTERPOLATED_MOVEMENT = 0x00000400;
            const INTERPOLATED_TURNING = 0x00000800;
            const INTERPOLATED_PITCHING = 0x00001000;
        }
    }

    impl Default for MovementExtraFlags {
        fn default() -> Self {
            Self::NONE
        }
    }

    impl BinRead for MovementExtraFlags {
        type Args<'a> = ();
        fn read_options<R: Read + Seek>(
            reader: &mut R,
            endian: Endian,
            _: Self::Args<'_>,
        ) -> BinResult<Self> {
            let bits = u16::read_options(reader, endian, ())?;
            Ok(MovementExtraFlags::from_bits_truncate(bits))
        }
    }

    impl BinWrite for MovementExtraFlags {
        type Args<'a> = ();
        fn write_options<W: Write + Seek>(
            &self,
            writer: &mut W,
            endian: Endian,
            _: Self::Args<'_>,
        ) -> BinResult<()> {
            u16::write_options(&self.bits(), writer, endian, ())
        }
    }

    #[derive(BinRead, BinWrite, PartialEq, Debug, Clone, Copy)]
    #[br(little)]
    #[bw(little)]
    pub struct JumpInfo {
        pub vertical_speed: f32,
        pub sin_angle: f32,
        pub cos_angle: f32,
        pub horizontal_speed: f32,
    }

    #[derive(BinRead, BinWrite, PartialEq, Debug, Clone)]
    #[br(little)]
    #[bw(little)]
    #[br(import(extra_flags: MovementExtraFlags))]
    pub struct TransportInfo {
        pub guid: PackedGuid,
        pub location: OrientedPoint3D,
        pub time: u32,
        pub seat: u8,
        #[br(if(extra_flags.contains(MovementExtraFlags::INTERPOLATED_MOVEMENT)))]
        pub time2: Option<u32>,
    }

    #[derive(BinRead, BinWrite, PartialEq, Debug, Clone)]
    #[br(little)]
    #[bw(little)]
    pub struct MovementInfo {
        pub movement_flags: MovementFlags,
        pub movement_extra_flags: MovementExtraFlags,
        pub time: u32,
        pub location: OrientedPoint3D,
        #[br(if(movement_flags.contains(MovementFlags::ONTRANSPORT)), args(movement_extra_flags))]
        pub transport: Option<TransportInfo>,
        // Present for swimming/flying, and also sometimes forced by extra flags.
        #[br(if(
            movement_flags.contains(MovementFlags::SWIMMING)
                || movement_flags.contains(MovementFlags::FLYING)
                || movement_extra_flags.contains(MovementExtraFlags::ALWAYS_ALLOW_PITCHING)
        ))]
        pub pitch: Option<f32>,
        pub fall_time: u32,
        #[br(if(movement_flags.contains(MovementFlags::JUMPING)))]
        pub jump_info: Option<JumpInfo>,
        #[br(if(movement_flags.contains(MovementFlags::SPLINE_ELEVATION)))]
        pub spline_elevation: Option<f32>,
    }
}
