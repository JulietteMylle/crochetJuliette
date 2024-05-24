<?php

namespace App\Entity;

use App\Repository\UserPartiePatronRepository;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: UserPartiePatronRepository::class)]
class UserPartiePatron
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\ManyToOne(inversedBy: 'userPartiePatrons')]
    #[ORM\JoinColumn(nullable: false)]
    private ?User $User = null;

    #[ORM\ManyToOne(inversedBy: 'userPartiePatrons')]
    #[ORM\JoinColumn(nullable: false)]
    private ?PartiePatron $id_PartiePatron = null;

    #[ORM\Column]
    private ?int $mailles = null;

    #[ORM\Column]
    private ?int $rangs = null;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getUser(): ?User
    {
        return $this->User;
    }

    public function setUser(?User $User): static
    {
        $this->User = $User;

        return $this;
    }

    public function getIdPartiePatron(): ?PartiePatron
    {
        return $this->id_PartiePatron;
    }

    public function setIdPartiePatron(?PartiePatron $id_PartiePatron): static
    {
        $this->id_PartiePatron = $id_PartiePatron;

        return $this;
    }

    public function getMailles(): ?int
    {
        return $this->mailles;
    }

    public function setMailles(int $mailles): static
    {
        $this->mailles = $mailles;

        return $this;
    }

    public function getRangs(): ?int
    {
        return $this->rangs;
    }

    public function setRangs(int $rangs): static
    {
        $this->rangs = $rangs;

        return $this;
    }
}
