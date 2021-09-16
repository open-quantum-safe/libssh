    # copy and authorize oqsdefault key pair
    file(COPY keys/id_oqsdefault DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_oqsdefault.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_oqsdefault.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize dilithium2 key pair
    file(COPY keys/id_dilithium2 DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_dilithium2.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_dilithium2.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize falcon512 key pair
    file(COPY keys/id_falcon512 DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_falcon512.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_falcon512.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize picnicl1full key pair
    file(COPY keys/id_picnicl1full DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_picnicl1full.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_picnicl1full.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize picnic3l1 key pair
    file(COPY keys/id_picnic3l1 DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_picnic3l1.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_picnic3l1.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize rainbowiclassic key pair
    file(COPY keys/id_rainbowiclassic DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_rainbowiclassic.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_rainbowiclassic.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize rainbowiiiclassic key pair
    file(COPY keys/id_rainbowiiiclassic DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_rainbowiiiclassic.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_rainbowiiiclassic.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize rainbowvclassic key pair
    file(COPY keys/id_rainbowvclassic DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_rainbowvclassic.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_rainbowvclassic.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize sphincsharaka128frobust key pair
    file(COPY keys/id_sphincsharaka128frobust DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_sphincsharaka128frobust.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_sphincsharaka128frobust.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize sphincssha256128frobust key pair
    file(COPY keys/id_sphincssha256128frobust DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_sphincssha256128frobust.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_sphincssha256128frobust.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize sphincsshake256128frobust key pair
    file(COPY keys/id_sphincsshake256128frobust DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_sphincsshake256128frobust.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_sphincsshake256128frobust.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize rsa3072-oqsdefault key pair
    file(COPY keys/id_rsa3072-oqsdefault DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_rsa3072-oqsdefault.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_rsa3072-oqsdefault.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize p256-oqsdefault key pair
    file(COPY keys/id_p256-oqsdefault DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_p256-oqsdefault.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_p256-oqsdefault.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize rsa3072-dilithium2 key pair
    file(COPY keys/id_rsa3072-dilithium2 DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_rsa3072-dilithium2.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_rsa3072-dilithium2.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize p256-dilithium2 key pair
    file(COPY keys/id_p256-dilithium2 DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_p256-dilithium2.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_p256-dilithium2.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize rsa3072-falcon512 key pair
    file(COPY keys/id_rsa3072-falcon512 DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_rsa3072-falcon512.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_rsa3072-falcon512.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize p256-falcon512 key pair
    file(COPY keys/id_p256-falcon512 DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_p256-falcon512.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_p256-falcon512.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize rsa3072-picnicl1full key pair
    file(COPY keys/id_rsa3072-picnicl1full DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_rsa3072-picnicl1full.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_rsa3072-picnicl1full.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize p256-picnicl1full key pair
    file(COPY keys/id_p256-picnicl1full DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_p256-picnicl1full.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_p256-picnicl1full.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize rsa3072-picnic3l1 key pair
    file(COPY keys/id_rsa3072-picnic3l1 DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_rsa3072-picnic3l1.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_rsa3072-picnic3l1.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize p256-picnic3l1 key pair
    file(COPY keys/id_p256-picnic3l1 DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_p256-picnic3l1.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_p256-picnic3l1.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize rsa3072-rainbowiclassic key pair
    file(COPY keys/id_rsa3072-rainbowiclassic DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_rsa3072-rainbowiclassic.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_rsa3072-rainbowiclassic.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize p256-rainbowiclassic key pair
    file(COPY keys/id_p256-rainbowiclassic DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_p256-rainbowiclassic.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_p256-rainbowiclassic.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize p384-rainbowiiiclassic key pair
    file(COPY keys/id_p384-rainbowiiiclassic DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_p384-rainbowiiiclassic.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_p384-rainbowiiiclassic.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize p521-rainbowvclassic key pair
    file(COPY keys/id_p521-rainbowvclassic DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_p521-rainbowvclassic.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_p521-rainbowvclassic.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize rsa3072-sphincsharaka128frobust key pair
    file(COPY keys/id_rsa3072-sphincsharaka128frobust DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_rsa3072-sphincsharaka128frobust.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_rsa3072-sphincsharaka128frobust.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize p256-sphincsharaka128frobust key pair
    file(COPY keys/id_p256-sphincsharaka128frobust DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_p256-sphincsharaka128frobust.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_p256-sphincsharaka128frobust.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize rsa3072-sphincssha256128frobust key pair
    file(COPY keys/id_rsa3072-sphincssha256128frobust DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_rsa3072-sphincssha256128frobust.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_rsa3072-sphincssha256128frobust.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize p256-sphincssha256128frobust key pair
    file(COPY keys/id_p256-sphincssha256128frobust DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_p256-sphincssha256128frobust.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_p256-sphincssha256128frobust.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize rsa3072-sphincsshake256128frobust key pair
    file(COPY keys/id_rsa3072-sphincsshake256128frobust DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_rsa3072-sphincsshake256128frobust.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_rsa3072-sphincsshake256128frobust.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")

    # copy and authorize p256-sphincsshake256128frobust key pair
    file(COPY keys/id_p256-sphincsshake256128frobust DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(COPY keys/id_p256-sphincsshake256128frobust.pub DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/home/bob/.ssh/ FILE_PERMISSIONS OWNER_READ OWNER_WRITE)
    file(READ keys/id_p256-sphincsshake256128frobust.pub CONTENTS)
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/home/alice/.ssh/authorized_keys "${CONTENTS}")
