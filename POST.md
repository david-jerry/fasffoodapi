# How To Clear Dokku `Out of space` Error

Most often we run into this type of error when we run out of available space to process our containers in dokku.

The reason is very self-explanatory as the statement suggests. The system does not have any remaining space on it to perform the required function from the docker tool. There exist various methods through which, memory can be cleared up in the system.

However with the code run in your dokku server you should be able to reclaim some storage space from unused containers and caches:

## System Prune

The system prune command is the most effective way to clean up space on your system for docker. This will remove any objects, images, etc that have not been utilized. To perform this task, simply run the command shown below:

```shell
sudo docker system prune -a
```

## Volume Prune

Instead of system prune, in some cases, it is better to utilize the Volume Prune command. With this command, all the volumes present locally on the system are removed. Volume prune will remove all the volumes that have not been utilized by any other container. Using the following command, a lot of space can be vacated:

```shell
sudo docker volume prune -a
```

#### NOTE

It is important to run with `sudo` right else you would get a permission error.
