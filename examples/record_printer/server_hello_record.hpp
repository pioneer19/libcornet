/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 *
 * This file is part of libcornet.
 *
 *  libcornet is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  libcornet is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with libcornet.  If not, see <https://www.gnu.org/licenses/>.
 */

const uint8_t tls13_server_hello_record[] = {
        0x16, 0x03, 0x03, 0x00, 0x5a,   // TlsPlaintext handshake, legacy version, length
        0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0xa6, 0x4b, 0xe1, 0x54, 0x72,
        0x33, 0x6c, 0xf8, 0x47, 0xa2, 0x16, 0xb5, 0x4c, 0x3a, 0x3f, 0xb5, 0xf6, 0xfc, 0x6c, 0x09, 0xd6,
        0xe3, 0x46, 0x14, 0x7c, 0x36, 0xcb, 0x69, 0xa6, 0xe9, 0x63, 0x7c, 0x00, 0x13, 0x01, 0x00, 0x00,
        0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x2d,
        0x76, 0x8c, 0x26, 0x19, 0xe7, 0x53, 0x3a, 0xeb, 0x8b, 0x2f, 0x47, 0xc5, 0x71, 0x4e, 0x74, 0x28,
        0xc1, 0xfb, 0x8a, 0x2a, 0xb1, 0xd3, 0x82, 0xcb, 0x45, 0xa3, 0xd0, 0x58, 0x0f, 0x42, 0x0c, 0x14,
        0x03, 0x03, 0x00, 0x01, 0x01, 0x17, 0x03, 0x03, 0x00, 0x17, 0x90, 0xe7, 0xc5, 0xdc, 0xbc, 0x03,
        0x22, 0x51, 0x56, 0x80, 0xc4, 0xd4, 0x6b, 0xc6, 0x36, 0x10, 0x70, 0x68, 0x22, 0x67, 0xf0, 0xdc,
        0x73, 0x17, 0x03, 0x03, 0x06, 0x8e, 0x8a, 0xc0, 0x4e, 0x74, 0x88, 0xb4, 0xa7, 0x2b, 0xc5, 0x50,
        0xb9, 0x92, 0x41, 0xc2, 0x61, 0xc2, 0xe1, 0x50, 0x12, 0x63, 0xc2, 0xe6, 0xe2, 0x88, 0x4f, 0x21,
        0xc5, 0x13, 0xcc, 0x6d, 0x8f, 0x54, 0x76, 0x66, 0x48, 0xa5, 0xa1, 0xe1, 0x8b, 0xef, 0xcc, 0xb4,
        0xb9, 0x1f, 0xd0, 0x29, 0x06, 0xbe, 0xd7, 0x5b, 0xe8, 0x70, 0x60, 0x59, 0x60, 0xb7, 0x84, 0xc2,
        0xac, 0x93, 0xf4, 0x5a, 0x7b, 0xbe, 0x40, 0xf2, 0x71, 0x70, 0x59, 0x6c, 0x9c, 0x2e, 0xfb, 0x41,
//            00d0 - 3e ae 93 17 fb 04 d6 6d-46 13 16 4d dc cf 2e c4   >......mF..M....
//            00e0 - 74 d1 e1 47 72 3e f9 4f-15 05 e5 20 53 44 e2 42   t..Gr>.O... SD.B
//            00f0 - 93 41 b4 39 c0 ec 04 28-1f 95 71 77 4e 71 76 ce   .A.9...(..qwNqv.
//            0100 - d7 bc ab 91 82 a8 4a 77-ab 71 df c3 a9 8d 7c 2a   ......Jw.q....|*
//                                                                                            0110 - b8 77 80 6a 9d ab 1f 4b-a0 07 23 19 70 f1 5b be   .w.j...K..#.p.[.
//            0120 - 1c 99 11 61 a9 9d 6c f1-b9 d2 28 e6 99 89 f1 1d   ...a..l...(.....
//            0130 - ff 4d dd e4 44 66 35 80-4a 08 5f 75 5b 65 5a a0   .M..Df5.J._u[eZ.
//            0140 - 0c f3 e0 7b 4f 7c f0 31-9f 1f b2 d1 0c 90 cc bb   ...{O|.1........
//                0150 - 2e 09 c6 a9 d3 8e 51 04-63 05 63 ad 2a b1 69 9f   ......Q.c.c.*.i.
//                0160 - c4 2e 67 2f e0 f9 94 08-19 51 75 55 0f 20 09 b3   ..g/.....QuU. ..
//                0170 - 13 b2 46 b3 d2 ab b6 80-ab 03 76 38 b2 ea e9 4e   ..F.......v8...N
//                0180 - 52 08 72 58 3a 1f e7 9c-7a b7 1a 2d 20 e1 ec ff   R.rX:...z..- ...
//                0190 - 20 b2 dc 9a 0c 5b 89 92-1d b1 0c 35 0d 7f c3 f7    ....[.....5....
//                01a0 - d2 67 ed 9f de 6f c9 de-b1 63 03 29 75 2c a2 7a   .g...o...c.)u,.z
//                01b0 - 58 a1 da ba 83 0a e4 b3-5b a9 f9 73 11 10 49 bb   X.......[..s..I.
//                01c0 - 73 3c 9e 9e 2b 7a 2a ea-c6 79 fb a7 ef 2b 8d 00   s<..+z*..y...+..
//                01d0 - 91 2a 3c c7 ba be 59 06-d0 44 bb b5 70 0e 46 2f   .*<...Y..D..p.F/
//                                                                               01e0 - 9c 56 6d 49 9b 04 6f d7-5d 79 4c 87 bb 58 82 4e   .VmI..o.]yL..X.N
//                01f0 - c7 bc c1 c1 ad 62 b0 fa-e3 d6 44 14 2d 19 ba 10   .....b....D.-...
//                0200 - a8 e7 18 67 b2 cb c0 cf-ec 27 87 41 95 ab 06 cd   ...g.....'.A....
//                0210 - e7 d8 9b 72 17 16 70 5f-41 38 ce 65 19 9e dd 25   ...r..p_A8.e...%
//                0220 - 4e 37 8d f9 0b 02 01 c6-3f d2 ed a4 fc 0f 9a 07   N7......?.......
//                0230 - e0 8e 8e ca 31 63 93 2a-01 84 2d c4 5c 6d d5 91   ....1c.*..-.\m..
//                0240 - 55 5b 05 5a 89 c8 36 bd-8a 68 0f bf 9b 65 2d b8   U[.Z..6..h...e-.
//                0250 - c8 16 99 4a 84 97 2c af-91 56 fa fa 11 50 5e b9   ...J..,..V...P^.
//                0260 - 38 41 02 b0 66 79 a8 1a-bb b9 93 f5 e6 28 83 44   8A..fy.......(.D
//                0270 - fe ba 12 e9 cc 9f 49 12-e1 e6 91 4d 02 45 23 21   ......I....M.E#!
//                                                                                                0280 - ed fc 0c b6 99 39 e5 5a-84 d3 1b c7 65 6c 80 d6   .....9.Z....el..
//                0290 - fe fd 5c 22 d1 74 3c 01-78 dd 83 da f8 13 51 82   ..\".t<.x.....Q.
//                02a0 - b7 3f c5 3f a1 6b 76 f3-8f 05 7d ff 70 41 5a a3   .?.?.kv...}.pAZ.
//            02b0 - ab e6 ee 1a e8 b9 af 34-64 c6 c0 15 81 dc 11 60   .......4d......`
//            02c0 - d4 81 b6 5e a0 df 58 8f-22 20 95 57 5a 2c f7 9b   ...^..X." .WZ,..
//            02d0 - 5a 37 94 2d 22 f2 a9 a0-9a c4 19 8f df 67 3a 9e   Z7.-"........g:.
//            02e0 - 1b 5b 2c da d9 ad 88 e1-31 a6 27 b8 73 d2 1b 13   .[,.....1.'.s...
//            02f0 - f2 95 75 c6 e6 6b a4 84-05 0b 93 c6 42 16 91 5a   ..u..k......B..Z
//            0300 - d3 98 26 94 3d c4 8e e8-01 e9 51 87 82 c2 c9 51   ..&.=.....Q....Q
//            0310 - e8 c3 c3 84 ae 2d 15 44-13 1b 3c 17 5f b1 ec e9   .....-.D..<._...
//            0320 - a1 a9 cb 65 5c e6 67 2b-bb 40 27 53 45 a2 8a e0   ...e\.g+.@'SE...
//            0330 - f3 d7 70 cf ae e8 58 72-cd 8f 70 7d 31 7b 96 51   ..p...Xr..p}1{.Q
//            0340 - 03 03 77 6e 8b 17 5c fc-ae d3 d3 a3 cb 43 e3 a5   ..wn..\......C..
//            0350 - be 95 a5 16 b0 81 18 ef-6a ea 78 a6 35 46 d5 39   ........j.x.5F.9
//            0360 - 1e 50 8d 11 67 16 3a e8-e2 ba e4 20 6f 43 cf 41   .P..g.:.... oC.A
//            0370 - 72 f1 18 79 81 27 57 fd-43 59 e4 10 b4 ba b5 ea   r..y.'W.CY......
//            0380 - 71 eb bb 8d 26 49 71 71-57 a7 7d 49 62 2a 05 19   q...&IqqW.}Ib*..
//        0390 - ed e6 62 8e e8 e4 91 4a-8e 71 b6 da 2e d0 05 7e   ..b....J.q.....~
//        03a0 - 29 da 91 9d 58 55 7d f9-08 41 b3 44 54 b1 bf 54   )...XU}..A.DT..T
//03b0 - 31 be 5c cb 3b 15 9f 06-91 69 03 a3 b2 73 c6 f8   1.\.;....i...s..
//03c0 - 64 82 89 e8 e2 c1 7c 18-6d 86 c8 3c a3 7c 91 89   d.....|.m..<.|..
//03d0 - 86 af f1 61 88 bd f4 93-b0 60 46 9c b6 af 81 a8   ...a.....`F.....
//03e0 - 5b 1e 5c 8b f1 d4 a9 67-47 f0 22 e0 57 67 6b a3   [.\....gG.".Wgk.
//03f0 - a3 6b 17 62 a7 40 2d f4-e1 1f 16 cd 4c 1b a9 ef   .k.b.@-.....L...
//0400 - 7e 07 dd 31 70 e7 17 db-b9 08 a5 6c 0d ae 74 d3   ~..1p......l..t.
//0410 - ff 15 ed 33 a3 41 a5 e0-cf bc 0b 16 f1 13 da 85   ...3.A..........
//0420 - 6c 2b 3b 24 7f 11 44 eb-92 d1 da 88 49 7d 6c 22   l+;$..D.....I}l"
//0430 - ed 98 46 39 49 5c d4 05-66 00 e1 b9 81 1b 51 de   ..F9I\..f.....Q.
//0440 - 14 c7 e7 82 19 12 ed 81-94 e9 8c 4f a4 b6 95 23   ...........O...#
//0450 - 0f 48 6d 9f ce a1 c5 ba-c0 de cc 6b 62 c9 ce 7e   .Hm........kb..~
//0460 - 44 2a 19 d9 84 a1 91 2e-b4 ed c6 2b d0 e3 47 e5   D*.........+..G.
//0470 - e4 fe 1c cc 59 cf 02 f3-73 ff 3f ab d8 dd f2 c7   ....Y...s.?.....
//0480 - 38 af 27 ad 22 72 d1 8f-3c 8b c7 5e e3 f2 ee a5   8.'."r..<..^....
//0490 - c5 ad ac 63 00 8f bf c1-3d 4f bd cc f3 e9 43 bf   ...c....=O....C.
//04a0 - b3 f0 65 a5 75 1e d5 67-57 82 7d 83 d5 9e 73 27   ..e.u..gW.}...s'
//04b0 - 62 c1 86 fb 04 89 a1 88-c2 ab f7 5b da cd 17 ad   b..........[....
//04c0 - dc 61 4c 55 3c d7 d6 9c-6d bc d0 84 b1 98 e7 2b   .aLU<...m......+
//04d0 - b3 51 ec 9f a5 00 5f 51-39 b6 72 bb 5c ed b3 c8   .Q...._Q9.r.\...
//04e0 - 04 27 09 88 f3 2d 59 2e-58 ab 9e 1b c1 12 26 6a   .'...-Y.X.....&j
//04f0 - cb 58 ae c0 3f eb dc fc-30 07 b8 ab 59 51 94 c6   .X..?...0...YQ..
//0500 - 20 97 a3 a9 c4 1c c7 e1-87 5c 85 34 cc 71 73 fe    ........\.4.qs.
//0510 - dc 44 bd a2 35 67 a2 2c-a9 b8 14 9c b1 a4 b1 88   .D..5g.,........
//0520 - f7 4f 40 4d 4a ea da 95-b0 1c 91 08 e9 ca 07 c2   .O@MJ...........
//0530 - c3 31 eb 04 63 cc 23 12-3a 7d 4d c3 27 ab 0b 6e   .1..c.#.:}M.'..n
//0540 - 0d 40 76 6c 17 53 91 27-d1 43 1c 81 af fd ef 53   .@vl.S.'.C.....S
//0550 - 7f 5e ba d8 cf 27 b7 7e-a5 77 64 59 a8 01 00 02   .^...'.~.wdY....
//0560 - 23 d2 1a 3b 95 35 14 8e-64 10 e7 0b df df 6a 59   #..;.5..d.....jY
//0570 - 68 0b e7 41 64 26 68 2c-d3 46 54 62 1a bb a4 95   h..Ad&h,.FTb....
//0580 - c3 bc 4d 91 ce 7c b5 31-6c 2b 54 5f 68 87 b4 c5   ..M..|.1l+T_h...
//0590 - 26 14 87 e6 0d c2 fc e9-da b8 e7 5a bd 24 ba f2   &..........Z.$..
//05a0 - 6b 91 d0 b0 7f 1f 17 64-c0 69 f1 e6 57 62 08 c2   k......d.i..Wb..
//05b0 - 3b 81 3e 0f 58 bf 14 36-4a 3f 0f 0d 05 ce 54 d5   ;.>.X..6J?....T.
//05c0 - 0e 64 ca 64 b1 a4 d3 63-6d 6c 85 98 58 9d 3a e5   .d.d...cml..X.:.
//05d0 - d6 5b a2 63 ab 66 e1 2a-4c 8b f5 d3 ab e3 33 2b   .[.c.f.*L.....3+
//05e0 - 8a 79 5a 42 5a 8c 35 1e-25 00 1a d7 5a 20 9d 57   .yZBZ.5.%...Z .W
//05f0 - 54 c1 c1 3d dd 4c 61 f8-87 a8 88 0f 36 02 c5 19   T..=.La.....6...
//0600 - 74 f4 85 e4 33 f5 f6 0e-40 dc 64 7e 14 4b 38 d6   t...3...@.d~.K8.
//0610 - 03 bc c6 dd d7 22 27 46-e4 f7 64 5f fd 39 bf 70   ....."'F..d_.9.p
//0620 - f5 dd 2f 19 84 44 d4 58-43 92 5b 7e 68 8d 9a 7e   ../..D.XC.[~h..~
//0630 - 91 63 7f 85 95 b9 5e 73-c8 17 73 f3 44 22 fc a4   .c....^s..s.D"..
//0640 - a2 c7 ca a1 ee 78 60 22-d7 2b 71 82 e1 ef be 2e   .....x`".+q.....
//0650 - e6 c0 9b c0 da 0d 6b 84-56 44 d3 38 22 10 85 d4   ......k.VD.8"...
//0660 - 52 5e 70 df 48 67 14 5a-ac 5e b9 b0 90 e5 92 c0   R^p.Hg.Z.^......
//0670 - 85 6c c8 f3 70 d7 80 29-c4 1e 89 e7 da 9d 0b 71   .l..p..).......q
//0680 - fb 80 32 bf b2 08 5b df-06 3d 8e 11 64 03 c9 b5   ..2...[..=..d...
//0690 - a1 7d c9 94 77 7f dd 76-8f 27 c0 e5 45 10 01 3a   .}..w..v.'..E..:
//06a0 - ce 3a 03 15 a6 12 d4 5b-07 96 a7 7a c2 53 4c 09   .:.....[...z.SL.
//06b0 - 9e dd 4b cb a6 db 62 07-94 46 dd ea 49 53 ed 6e   ..K...b..F..IS.n
//06c0 - 51 04 37 9f ef 69 23 b6-0e 79 be f1 7f 96 38 e4   Q.7..i#..y....8.
//06d0 - cf 8d 01 30 1b 3a 40 f4-64 e9 7f 4a f9 21 5e 82   ...0.:@.d..J.!^.
//06e0 - 51 ee 26 cb 60 75 13 58-0c ef b1 ba d0 73 c0 29   Q.&.`u.X.....s.)
//06f0 - 58 f0 6c 33 34 b5 27 2a-c3 76 da 9e ce fa a8 40   X.l34.'*.v.....@
//0700 - 8d 8a b0 47 cf 09 a4 9c-b6 f6 b6 47 1a c8 2e 35   ...G.......G...5
//0710 - 6b 6e f4 d6 17 03 03 02-19 0e 86 0f d8 f1 2b 85   kn............+.
//0720 - 7d ad 0a 4c e7 c3 d9 f7-87 d6 9f 4d b0 c2 c3 f3   }..L.......M....
//0730 - 82 b1 98 4a 89 8c 99 a0-7d 57 c3 cf bb 13 be 81   ...J....}W......
//0740 - 66 c7 95 18 da 35 c4 e4-03 c9 0e f3 82 41 b3 b5   f....5.......A..
//0750 - 4d 13 39 29 04 1f 8b fe-96 35 1b 27 46 34 88 98   M.9).....5.'F4..
//0760 - db 58 18 bd e3 56 5c ef-e6 03 f6 ee 31 1e ca fe   .X...V\.....1...
//0770 - f7 ad eb 85 d6 82 e5 57-a4 73 c0 41 b5 95 fc d4   .......W.s.A....
//0780 - f5 09 5d fa c8 df 8e f2-12 c5 c1 84 ec ce 4a 11   ..]...........J.
//0790 - 07 ca 8e 07 01 0c 00 02-e6 1b 55 49 63 5f 00 f3   ..........UIc_..
//07a0 - 62 70 b1 d0 ac 12 ab 0a-60 61 c0 06 9e 9b ef 6c   bp......`a.....l
//07b0 - c0 ff 84 d7 a6 c7 01 62-20 03 ba 69 7c 8d 3d e6   .......b ..i|.=.
//07c0 - 14 49 56 9c 73 26 40 ac-ed e3 42 82 6a 8c bf f2   .IV.s&@...B.j...
//07d0 - c6 28 41 7c 06 4c 06 bd-56 10 e5 57 6b ad 94 39   .(A|.L..V..Wk..9
//07e0 - f4 02 9a fb b8 f1 f0 f4-97 e7 e9 bd 25 9b 71 0c   ............%.q.
//07f0 - 29 60 b1 22 c6 26 80 82-25 c0 f0 78 7d 6b 23 97   )`.".&..%..x}k#.
//0800 - d7 a0 ee 3b 00 d4 11 d7-52 fa dc bd d6 13 0e 69   ...;....R......i
//0810 - 18 71 5b 85 8b 20 7b 20-09 14 b1 49 c0 95 16 8d   .q[.. { ...I....
//0820 - e1 c2 09 93 4a 2e 09 2d-43 40 a1 d7 45 e4 d8 63   ....J..-C@..E..c
//0830 - 3f cd 68 0a e0 83 dc 75-5a fe 07 23 d6 92 05 e9   ?.h....uZ..#....
//0840 - 3a d2 bd f6 02 fe 7e 26-9a 17 53 6e cf 49 2c d6   :.....~&..Sn.I,.
//0850 - 77 59 56 34 70 5c 38 25-d4 43 69 a2 14 13 f5 6b   wYV4p\8%.Ci....k
//0860 - 1a 85 69 71 db 8c 19 9a-c6 fa c7 48 43 26 84 24   ..iq.......HC&.$
//0870 - 41 8c e0 e1 2f ed a3 7e-49 da 4d 7b 54 47 5b 62   A.../..~I.M{TG[b
//0880 - 0a e9 fe b9 6c bc 7d ae-be 7f 48 b6 a2 11 33 f2   ....l.}...H...3.
//0890 - 35 07 f4 9b c4 16 02 5f-7d cb 69 18 9e c2 b1 24   5......_}.i....$
//08a0 - 50 32 d5 38 26 86 7f 78-46 1b d2 62 7f f4 f1 09   P2.8&..xF..b....
//08b0 - 47 d2 d5 fe 7f 4c 5f e7-eb 84 af 94 b4 ca 0b 35   G....L_........5
//08c0 - 9e da ee be af 14 d2 b3-c1 cb 92 01 2d 5d bd 1d   ............-]..
//08d0 - bf 0c 5e 2b 97 13 9a f1-02 d4 88 47 b1 2a 5a b0   ..^+.......G.*Z.
//08e0 - 9f 78 d8 88 03 ae 98 2d-36 5c 1a 3d e8 b0 90 27   .x.....-6\.=...'
//08f0 - 47 66 b7 da ae f3 d1 61-3b de 6e 7b f1 c9 89 2b   Gf.....a;.n{...+
//0900 - ec f2 e2 bc 8f 22 b6 e0-2c 9d b7 0e 7f 0b 77 01   ....."..,.....w.
//0910 - 37 24 da b4 bf 0d e8 36-a5 4d 1b ba cc d7 f9 8e   7$.....6.M......
//0920 - b0 a2 95 15 c2 d7 ca 30-5b 4c a5 88 31 79 98 88   .......0[L..1y..
//0930 - f7 f6 17 03 03 00 35 86-26 d6 e4 b3 a5 e4 ee 0c   ......5.&.......
//0940 - 88 9b 0a 4d fc 30 7c c0-e8 33 97 d2 ae 28 c1 79   ...M.0|..3...(.y
//0950 - 12 f4 4a 2a 74 40 55 65-34 1e 4a 19 bb 70 2c da   ..J*t@Ue4.J..p,.
//0960 - 5b db ab e1 00 56 6d dd-04 34 25 46               [....Vm..4%F
//        read from 0x556bee44da80 [0x556bee454333] (5 bytes => -1 (0xFFFFFFFFFFFFFFFF))

};
