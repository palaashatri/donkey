add_executable(donkey-cli
  main.cpp
)
target_link_libraries(donkey-cli PRIVATE donkey::binary)
donkey_apply_warnings(donkey-cli)
