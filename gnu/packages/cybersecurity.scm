;;; GNU Guix --- Functional package management for GNU
;;; Copyright © 2020 Jakub Kądziołka <kuba@kadziolka.net>
;;;
;;; This file is part of GNU Guix.
;;;
;;; GNU Guix is free software; you can redistribute it and/or modify it
;;; under the terms of the GNU General Public License as published by
;;; the Free Software Foundation; either version 3 of the License, or (at
;;; your option) any later version.
;;;
;;; GNU Guix is distributed in the hope that it will be useful, but
;;; WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU General Public License for more details.
;;;
;;; You should have received a copy of the GNU General Public License
;;; along with GNU Guix.  If not, see <http://www.gnu.org/licenses/>.

(define-module (gnu packages cybersecurity)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix packages)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix build-system python)
  #:use-module (gnu packages)
  #:use-module (gnu packages avr)
  #:use-module (gnu packages bioinformatics)
  #:use-module (gnu packages cross-base)
  #:use-module (gnu packages emulators)
  #:use-module (gnu packages engineering)
  #:use-module (gnu packages python-crypto)
  #:use-module (gnu packages python-web)
  #:use-module (gnu packages python-xyz)
  #:use-module (gnu packages time))

(define-public ropgadget
  (package
    (name "ropgadget")
    (version "6.3")
    (source
     (origin
       (method url-fetch)
       (uri (pypi-uri "ROPGadget" version))
       (sha256
        (base32 "0v34w88if3p4vn46aby24msfnxj6znmkf4848n4d24jnykxcsqk9"))))
    (build-system python-build-system)
    (propagated-inputs
     `(("python-capstone" ,python-capstone)))
    (home-page "http://shell-storm.org/project/ROPgadget/")
    (synopsis "Semiautomatic return oriented programming")
    (description
     "This tool lets you search for @acronym{ROP, Return Oriented Programming}
gadgets in binaries.  Some facilities are included for automatically generating
chains of gadgets to execute system calls.")
    (license license:bsd-3)))

(define-public python-pwntools
  (package
    (name "python-pwntools")
    (version "4.1.1")
    (source
      (origin
        (method git-fetch)
        (uri (git-reference
               (url "https://github.com/Gallopsled/pwntools")
               (commit version)))
        (file-name (git-file-name name version))
        (sha256
         (base32
          "101whqdfj415h0f4b9hz2jrwny44b0jdd9jmbh6rzz5w1yp41d5v"))
        (patches (search-patches "python-pwntools-guix-wrappers.patch"))))
    (build-system python-build-system)
    (arguments
     `(#:tests? #f)) ; Tests require networking and custom sshd configuration
    (propagated-inputs
     `(("paramiko" ,python-paramiko)
       ("mako" ,python-mako)
       ("pyelftools" ,python-pyelftools)
       ("capstone" ,python-capstone)
       ("ropgadget" ,ropgadget)
       ("pyserial" ,python-pyserial)
       ("requests" ,python-requests)
       ("pygments" ,python-pygments)
       ("pysocks" ,python-pysocks)
       ("dateutil" ,python-dateutil)
       ("packaging" ,python-packaging)
       ("psutil" ,python-psutil)
       ("intervaltree" ,python-intervaltree)
       ("sortedcontainers" ,python-sortedcontainers)
       ("unicorn" ,unicorn "python")

       ;; See https://docs.pwntools.com/en/stable/install/binutils.html
       ;; All architectures recognized by pwntools are included.
       ("binutils:aarch64" ,(cross-binutils "aarch64-linux-gnu"))
       ("binutils:alpha" ,(cross-binutils "alpha-linux-gnu"))
       ("binutils:arm" ,(cross-binutils "arm-linux-gnueabihf"))
       ;; TODO: AVR binutils aren't detected,
       ;; see https://github.com/Gallopsled/pwntools/pull/1536
       ("binutils:avr" ,avr-binutils)
       ("binutils:cris" ,(cross-binutils "cris-linux-gnu"))
       ("binutils:i686" ,(cross-binutils "i686-linux-gnu"))
       ("binutils:ia64" ,(cross-binutils "ia64-linux-gnu"))
       ("binutils:m68k" ,(cross-binutils "m68k-linux-gnu"))
       ("binutils:mips" ,(cross-binutils "mipsel-linux-gnu"))
       ("binutils:mips64" ,(cross-binutils "mips64el-linux-gnu"))
       ;; TODO: MSP430 doesn't work for the same reason as AVR.
       ("binutils:msp430" ,(cross-binutils "msp430"))
       ("binutils:powerpc" ,(cross-binutils "powerpc-linux-gnu"))
       ("binutils:powerpc64" ,(cross-binutils "powerpc64-linux-gnu"))
       ;; TODO: Attempting to assemble code for arch='s390' complains
       ;; about bfdname
       ("binutils:s390" ,(cross-binutils "s390-linux-gnu"))
       ("binutils:sparc" ,(cross-binutils "sparc-linux-gnu"))
       ("binutils:sparc64" ,(cross-binutils "sparc64-linux-gnu"))
       ;; TODO: Should VAX use a -linux-gnu target, or just "vax"?
       ("binutils:vax" ,(cross-binutils "vax-linux-gnu"))
       ("binutils:x86_64" ,(cross-binutils "x86_64-linux-gnu"))))
    (native-inputs
     `(("tox" ,python-tox)))
    (home-page "https://github.com/Gallopsled/pwntools")
    (synopsis "CTF framework and exploit development library")
    (description "Pwntools is a CTF framework and exploit development library.
Written in Python, it is designed for rapid prototyping and development, and
intended to make exploit writing as simple as possible.")
    ;; See LICENSE-pwntools.txt in the source distribution.
    (license (list license:expat license:bsd-2 license:gpl2+))))
