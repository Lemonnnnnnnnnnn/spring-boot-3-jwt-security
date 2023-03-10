package pers.lyc.model.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import pers.lyc.model.entity.User;

@Repository
public interface UserRepository extends JpaRepository<User,Integer> {
    User findByUsername(String username);
}
