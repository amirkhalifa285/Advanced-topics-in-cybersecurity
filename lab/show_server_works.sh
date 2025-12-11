echo "=== Compiled Binaries ===" && ls -lh zookd* && \
echo -e "\n=== Python Packages ===" && python3 -c "import flask, sqlalchemy, web3; print('Flask:', flask.__version__, '\nSQLAlchemy:', sqlalchemy.__version__, '\nWeb3:', web3.__version__)" && \
echo -e "\n=== Solidity Compiler ===" && solc --version | head -3 && \
echo -e "\n=== Starting Server ===" && ./zookd 8080 &
sleep 2
echo -e "\n=== Server Running ===" && ps aux | grep "[z]ookd" && \
echo -e "\n=== Server Response ===" && curl -s http://localhost:8080/ | head -5
