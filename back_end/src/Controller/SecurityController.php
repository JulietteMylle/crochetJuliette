<?php

namespace App\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;

class SecurityController extends AbstractController
{
    #[Route('/register', name: 'register')]
    public function register(UserRepository $userRepository, Request $request, EntityManagerInterface $entityManager, UserPasswordHasherInterface $passwordHasher): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        $username = $data['username'];
        $email = $data['email'];
        $password = $data['password'];

        if (!$username || !$email || !$password) {
            return new JsonResponse(['message' => 'Tous les champs sont obligatoires.'], JsonResponse::HTTP_BAD_REQUEST);
        }

        if (strlen($password) < 13 || !preg_match('/[A-Z]/', $password) || !preg_match('/[a-z]/', $password) || !preg_match('/[^A-Za-z0-9]/', $password)) {
            return new JsonResponse(['message' => 'Le mot de passe doit contenir au moins 13 caractères, une lettre majuscule, une lettre minuscule et un caractère spécial.'], JsonResponse::HTTP_BAD_REQUEST);
        }

        $user = new User();
        $user->setUsername($username);
        $user->setEmail($email);
        $user->setPassword($passwordHasher->hashPassword($user, $password));
        $user->setRoles(["ROLE_USER"]);

        $entityManager->persist($user);
        $entityManager->flush();

        return new JsonResponse(['message' => 'Votre compte a bien été créé'], JsonResponse::HTTP_CREATED);
    }
}
