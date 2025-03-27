#!/bin/bash

if [ -f "csprng_tiny_aes.h" ]; then
	# in this case, the AES-NI is being used, so we switch to tiny-AES

	mv csprng.h csprng_aes_ni.h
	mv csprng.cpp csprng_aes_ni.cpp

    mv csprng_tiny_aes.h csprng.h
    mv csprng_tiny_aes.cpp csprng.cpp

	make clean

	echo "Now using tiny-AES"

else

	if [ -f "csprng_aes_ni.h" ]; then
		# in this case, the tiny-AES is being used, so we switch to AES-NI

		mv csprng.h csprng_tiny_aes.h
		mv csprng.cpp csprng_tiny_aes.cpp

		mv csprng_aes_ni.h csprng.h
		mv csprng_aes_ni.cpp csprng.cpp
	
		make clean
	
		echo "Now using AES-NI"
	fi
fi

