<?php
$usuario=htmlentities("jordi");//$_POST['name'];
$userdef= filter_var($usuario, FILTER_SANITIZE_STRING);
$password=htmlentities("meh");//$_POST['password'];
$passdef= filter_var($password, FILTER_SANITIZE_STRING);
//session_start();
//$_SESSION['usuario']=$usuario;

$conexion=mysqli_connect("localhost","alumne","alumne","usuaris");
$consulta='SELECT * FROM usuaris where dni="'.$userdef.'" and password="'.$passdef.'"';
$resultado=mysqli_query($conexion,$consulta);
$filas=mysqli_num_rows($resultado);

if($filas){
    echo "usuario correcto";
}else{
    echo "usuario erronio";
}
mysqli_free_result($resultado);
mysqli_close($conexion);
?>

