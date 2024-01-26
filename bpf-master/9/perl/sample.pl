sub end {
  if ($_[0]>0) {
    print("".$_[0]."\n");
    end ($_[0]-1);
    return($_[0]);
  }
  print("end\n");
  return($_[0]);
}

sub start {
  print("start\n");
  while(1) {
    end($_[0]);
    sleep(1);
  }
}

start(3);
