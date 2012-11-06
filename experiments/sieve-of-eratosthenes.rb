#!/usr/bin/env ruby

def primesUpto(max) 
  num = [1, 2, 3]

  return [] if max < 1
  
  if max < 3; 
    (3 - max).times do num.pop end
    return num
  end
  
  # Push all the odds, no need to waste cycles stripping evens
  num.push(num[-1] + 2) until (num[-1] + 2) > max
  
  # For each prime from 3 upto sqrt(max) 
  # Strip n * currentPrime  for n from 2 upto max/currentPrime
  i = 2; until num[i] >= (Math.sqrt(max).floor)
    puts "Stripping multiples of #{num[i]}"
    ((max/num[i]-2).floor).times do |j|
      (num.delete((num[i])*(j+2)))
    end; i+=1 
  end; return num
end

puts primesUpto(50000)

