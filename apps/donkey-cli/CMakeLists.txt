add_executable(donkey-cli
  commands.cpp
  main.cpp
)
target_link_libraries(donkey-cli PRIVATE donkey::analysis)
donkey_apply_warnings(donkey-cli)
