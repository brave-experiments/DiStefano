library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.STD_LOGIC_UNSIGNED.ALL;
use IEEE.STD_LOGIC_ARITH.ALL;

library IEEE;
use IEEE.STD_LOGIC_1164.ALL;

entity ModAdd256 is
  generic( size : integer := 256);
  port(    x, y : in STD_LOGIC_VECTOR(size-1 downto 0); -- x, y < p
           p : in STD_LOGIC_VECTOR(size-1 downto 0);
           result : out STD_LOGIC_VECTOR(size-1 downto 0));
end ModAdd256;

architecture Behavioral of ModAdd256 is
  signal t1, t2, x_long, y_long, p_long : STD_LOGIC_VECTOR(size+1 downto 0);
  
begin

  x_long <= "00" & x;
  y_long <= "00" & y;
  p_long <= "00" & p;
    
  t1 <= x_long + y_long;
  t2 <= t1 - p_long;

  mux: process(t1, t2)
  begin
    if t2(size+1) = '1' then
      result <= t1(size-1 downto 0);
    else
      result <= t2(size-1 downto 0);
    end if;
  end process;

end Behavioral;
