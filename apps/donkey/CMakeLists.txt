add_executable(donkey
  main.cpp
)
target_link_libraries(donkey PRIVATE donkey::ui)
donkey_apply_warnings(donkey)
