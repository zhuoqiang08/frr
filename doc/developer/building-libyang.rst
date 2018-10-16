Build and install libyang:

.. code-block:: shell

   wget https://github.com/CESNET/libyang/archive/v0.16-r1.tar.gz
   tar xvf v0.16-r1.tar.gz
   cd libyang-0.16-r1
   mkdir build; cd build
   cmake -DENABLE_LYD_PRIV=ON ..
   make
   sudo make install

Note: please check the `libyang build requirements
<https://github.com/CESNET/libyang/blob/master/README.md#build-requirements>`_
first.
