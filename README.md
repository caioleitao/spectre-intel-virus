# Spectre Intel Virus
DONT RUN IT WITHOUT KNOW, IS A EXAMPLE VIRUS!
<BR/>
THIS FILES WAS CREATED FOR EDUCATIONAL AND LEARNING PURPOSES ONLY

NAO RODE ISSO SEM SABER, ISSO E UM EXEMPLO DE VIRUS!
<BR/>
ESSES ARQUIVOS FORAM CRIADOS PARA SOMENTE PROPOSITOS EDUCACIONAIS E DE APRENDIZAGEM

<BR/>
Como executar:
<br/>
Modifique o arquivo /etc/default/grub e coloque em GRUB_CMDLINE_LINUX_DEFAULT a sequinte opcao: mitigations=off e reinicnie o computador, com isso a cpu estara vuneravel a ataques de spectre 
<br/>
Compile o arquivo com o seguinte comando dentro do diretorio do projeto: gcc -o spectre main.cpp
<br/>
e execute o arquivo com ./spectre
