library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.STD_LOGIC_UNSIGNED.ALL;
use IEEE.STD_LOGIC_ARITH.ALL;

library IEEE;
use IEEE.STD_LOGIC_1164.ALL;

entity Inc128 is
  generic( size : integer := 128);
  port(    x : in STD_LOGIC_VECTOR(size-1 downto 0);
           result : out STD_LOGIC_VECTOR(size-1 downto 0));
end Inc128;

architecture Behavioral of Inc128 is
begin
  result <= x + 1; -- deliberately truncate. 
end Behavioral;
